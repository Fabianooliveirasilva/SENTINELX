"""Notification delivery: e-mail and signed webhooks, from the ``notifications`` outbox.

Security properties:

* Webhook signing secrets are generated server-side, shown once, and stored
  encrypted (Fernet; key derived from ``SECRET_KEY`` with HKDF).
* Webhook destinations are resolved at delivery time and every address must pass
  the network policy (public addresses only, plus explicitly allowed networks):
  the request goes to the pinned IP with the original ``Host`` and TLS SNI, so a
  DNS answer cannot redirect a delivery to an internal service (SSRF / rebinding).
* Redirects are never followed, proxies from the environment are ignored, and
  response bodies are not read or stored.
* Each payload is signed: ``X-SentinelX-Signature: t=<unix>,v1=<hex>`` where
  ``v1 = HMAC-SHA256(secret, "<t>." + body)``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final
from urllib.parse import urlsplit, urlunsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.core.logging import get_logger
from app.models import Notification, NotificationChannel, SecurityEvent
from app.services.email import EmailMessage, EmailSender
from sentinelx_security.scope import NetworkPolicy, ResolutionError, Resolver
from sentinelx_security.scope.network_policy import parse_lab_networks

logger = get_logger(__name__)

SIGNATURE_HEADER: Final = "X-SentinelX-Signature"
MAX_URL_LENGTH: Final = 2000
LEASE: Final = timedelta(minutes=5)
MAX_BACKOFF: Final = timedelta(hours=6)
USER_AGENT: Final = "SentinelX-Webhook/1"


def utcnow() -> datetime:
    return datetime.now(UTC)


class DeliveryError(Exception):
    """A delivery failure with a message that is safe to store and show."""

    def __init__(self, message: str, *, retryable: bool = True, status: int | None = None):
        super().__init__(message)
        self.message = message[:300]
        self.retryable = retryable
        self.status = status


# --------------------------------------------------------------------- secrets


class SecretBox:
    """Symmetric encryption for secrets at rest (channel signing secrets)."""

    def __init__(self, secret_key: str) -> None:
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"sentinelx/notification-channel-secrets/v1",
        ).derive(secret_key.encode())
        self._fernet = Fernet(base64.urlsafe_b64encode(key))

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken as exc:  # e.g. SECRET_KEY rotated
            raise DeliveryError(
                "The signing secret cannot be decrypted; rotate it.", retryable=False
            ) from exc


def new_signing_secret() -> str:
    return "whsec_" + secrets.token_urlsafe(32)


def sign(secret: str, timestamp: int, body: bytes) -> str:
    digest = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return f"t={timestamp},v1={digest.hexdigest()}"


# --------------------------------------------------------------------- webhooks


def validate_webhook_url(url: str, *, allow_http: bool) -> str:
    """Static checks at configuration time; the network check happens per delivery."""
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        raise ValueError("The URL is too long.")
    parts = urlsplit(url)
    schemes = {"https", "http"} if allow_http else {"https"}
    if parts.scheme not in schemes:
        raise ValueError("Webhook URLs must use https.")
    if not parts.hostname:
        raise ValueError("The URL has no host.")
    if parts.username or parts.password:
        raise ValueError("Credentials in the URL are not allowed; use the signing secret.")
    if parts.fragment:
        raise ValueError("Fragments are not allowed in webhook URLs.")
    try:
        _ = parts.port
    except ValueError as exc:
        raise ValueError("The URL has an invalid port.") from exc
    return url


@dataclass(frozen=True, slots=True)
class WebhookResult:
    status: int
    address: str


class WebhookClient:
    def __init__(
        self,
        resolver: Resolver,
        policy: NetworkPolicy,
        *,
        timeout_seconds: float,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._resolver = resolver
        self._policy = policy
        self._timeout = timeout_seconds
        self._transport = transport

    async def _pin(self, host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            try:
                addresses = await self._resolver.resolve(host)
            except ResolutionError as exc:
                raise DeliveryError(f"DNS resolution failed ({exc.code}).") from exc
        if not addresses:
            raise DeliveryError("The webhook host has no addresses.")
        # Every answer must be acceptable: a mixed answer is a rebinding signal.
        for address in addresses:
            verdict = self._policy.check(address)
            if not verdict.allowed:
                raise DeliveryError(
                    f"Destination address refused by policy ({verdict.reason}).",
                    retryable=False,
                )
        return addresses[0]

    async def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> WebhookResult:
        parts = urlsplit(url)
        host = parts.hostname or ""
        address = await self._pin(host)
        literal = f"[{address.compressed}]" if address.version == 6 else address.compressed
        netloc = f"{literal}:{parts.port}" if parts.port else literal
        pinned = urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))
        host_header = f"{host}:{parts.port}" if parts.port else host
        extensions = {"sni_hostname": host} if parts.scheme == "https" else {}
        try:
            async with httpx.AsyncClient(
                transport=self._transport,
                timeout=self._timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                request = client.build_request(
                    "POST",
                    pinned,
                    content=body,
                    headers={**headers, "Host": host_header},
                    extensions=extensions,
                )
                response = await client.send(request, stream=True)
                await response.aclose()  # the body is never read
        except httpx.TimeoutException as exc:
            raise DeliveryError("The webhook endpoint timed out.") from exc
        except httpx.HTTPError as exc:
            raise DeliveryError(f"Connection failed ({type(exc).__name__}).") from exc
        status = response.status_code
        if 200 <= status < 300:
            return WebhookResult(status=status, address=address.compressed)
        retryable = status >= 500 or status in (408, 429)
        raise DeliveryError(
            f"The endpoint answered HTTP {status}.", retryable=retryable, status=status
        )


def webhook_policy(settings: Settings) -> NetworkPolicy:
    return NetworkPolicy(parse_lab_networks(settings.webhook_allowed_networks))


# --------------------------------------------------------------------- payloads


def event_payload(event: SecurityEvent) -> dict[str, Any]:
    return {
        "id": str(event.id),
        "type": event.event_type,
        "severity": event.severity,
        "title": event.title,
        "occurred_at": event.occurred_at.isoformat(),
        "project_id": str(event.project_id),
        "asset_id": str(event.asset_id) if event.asset_id else None,
        "finding_id": str(event.finding_id) if event.finding_id else None,
        "scan_job_id": str(event.scan_job_id) if event.scan_job_id else None,
        "actor": event.actor_email,
        "details": event.details,
    }


def email_for(event: SecurityEvent, settings: Settings) -> tuple[str, str]:
    subject = f"[SentinelX] {event.severity.upper()}: {event.title}"[:200]
    lines = [
        f"Event:     {event.event_type}",
        f"Severity:  {event.severity}",
        f"Occurred:  {event.occurred_at.isoformat()}",
        f"Title:     {event.title}",
    ]
    if event.actor_email:
        lines.append(f"Actor:     {event.actor_email}")
    for key, value in sorted(event.details.items()):
        if value not in (None, "", [], {}):
            lines.append(f"{key}: {json.dumps(value, default=str)[:500]}")
    base = settings.frontend_base_url.rstrip("/")
    lines += [
        "",
        f"Timeline: {base}/projects/{event.project_id}/events",
        "",
        "Automated notification from SentinelX. Scanner-derived text is untrusted data.",
    ]
    return subject, "\n".join(lines)


# --------------------------------------------------------------------- delivery


class Deliverer:
    def __init__(
        self,
        settings: Settings,
        email: EmailSender,
        webhooks: WebhookClient,
        box: SecretBox | None = None,
    ) -> None:
        self._settings = settings
        self._email = email
        self._webhooks = webhooks
        self._box = box or SecretBox(settings.secret_key.get_secret_value())

    async def send(self, notification: Notification) -> int | None:
        channel = notification.channel
        event = notification.event
        if not channel.enabled:
            raise DeliveryError("The channel is disabled.", retryable=False)
        if channel.kind == "email":
            subject, body = email_for(event, self._settings)
            recipients = [str(r) for r in channel.config.get("recipients", [])]
            if not recipients:
                raise DeliveryError("The channel has no recipients.", retryable=False)
            for recipient in recipients:
                try:
                    await self._email.send(EmailMessage(to=recipient, subject=subject, body=body))
                except OSError as exc:
                    raise DeliveryError(f"E-mail delivery failed ({type(exc).__name__}).") from exc
            return None
        if not channel.secret_encrypted:
            raise DeliveryError("The channel has no signing secret.", retryable=False)
        try:
            # Re-checked per delivery: a channel created in development with http://
            # must not deliver in cleartext once the deployment runs in production.
            url = validate_webhook_url(
                str(channel.config.get("url", "")), allow_http=not self._settings.is_production
            )
        except ValueError as exc:
            raise DeliveryError(f"Invalid webhook URL: {exc}", retryable=False) from exc
        payload = json.dumps(
            {"delivery_id": str(notification.id), "event": event_payload(event)},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        timestamp = int(time.time())
        result = await self._webhooks.post(
            url,
            payload,
            {
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
                "X-SentinelX-Event": event.event_type,
                "X-SentinelX-Delivery": str(notification.id),
                SIGNATURE_HEADER: sign(
                    self._box.decrypt(channel.secret_encrypted), timestamp, payload
                ),
            },
        )
        return result.status


def backoff(attempts: int) -> timedelta:
    return min(timedelta(minutes=2 ** max(attempts - 1, 0)), MAX_BACKOFF)


async def deliver_due(
    session: AsyncSession, deliverer: Deliverer, settings: Settings
) -> dict[str, int]:
    """Deliver due notifications. Rows are leased first so workers never double-send."""
    now = utcnow()
    ids = list(
        (
            await session.execute(
                select(Notification.id)
                .where(Notification.status == "pending", Notification.next_attempt_at <= now)
                .order_by(Notification.next_attempt_at)
                .limit(settings.notification_batch_size)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    if not ids:
        return {"sent": 0, "retrying": 0, "failed": 0}
    await session.execute(
        update(Notification).where(Notification.id.in_(ids)).values(next_attempt_at=now + LEASE)
    )
    await session.commit()

    counts = {"sent": 0, "retrying": 0, "failed": 0}
    for notification_id in ids:
        notification = (
            await session.execute(
                select(Notification)
                .where(Notification.id == notification_id)
                .options(selectinload(Notification.event), selectinload(Notification.channel))
            )
        ).scalar_one_or_none()
        if notification is None or notification.status != "pending":
            continue
        notification.attempts += 1
        try:
            notification.response_status = await deliverer.send(notification)
        except DeliveryError as exc:
            notification.last_error = exc.message
            notification.response_status = exc.status
            if exc.retryable and notification.attempts < settings.notification_max_attempts:
                notification.next_attempt_at = utcnow() + backoff(notification.attempts)
                counts["retrying"] += 1
            else:
                notification.status = "failed"
                counts["failed"] += 1
            logger.warning(
                "notification_delivery_failed",
                notification_id=str(notification.id),
                channel_kind=notification.channel.kind,
                attempts=notification.attempts,
                error=exc.message,
            )
        else:
            notification.status = "sent"
            notification.sent_at = utcnow()
            notification.last_error = None
            counts["sent"] += 1
        await session.commit()
    return counts


async def queue_test(
    session: AsyncSession, channel: NotificationChannel, event: SecurityEvent
) -> Notification:
    notification = Notification(
        id=uuid.uuid4(),
        project_id=channel.project_id,
        event_id=event.id,
        rule_id=None,
        channel_id=channel.id,
        status="pending",
        next_attempt_at=utcnow(),
    )
    session.add(notification)
    await session.flush()
    return notification
