"""Unit tests for notification primitives: secrets, signatures, URLs, SMTP, rule matching."""

from __future__ import annotations

import hashlib
import hmac
import ssl
import uuid
from datetime import timedelta
from typing import Any, ClassVar

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.models import AlertRule, SecurityEvent
from app.services.email import EmailMessage, SmtpEmailSender, build_email_sender
from app.services.events import rule_matches, severity_at_least
from app.services.notifications import (
    DeliveryError,
    SecretBox,
    backoff,
    new_signing_secret,
    sign,
    validate_webhook_url,
)


def _settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "secret_key": "unit-test-secret-key-0123456789abcdef",
        "database_url": "postgresql+asyncpg://u:p@localhost/db",
        "redis_url": "redis://localhost:6379/0",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_secret_box_round_trip_and_key_binding() -> None:
    box = SecretBox("first-secret-key-0123456789abcdefgh")
    secret = new_signing_secret()
    token = box.encrypt(secret)
    assert secret not in token
    assert box.decrypt(token) == secret
    with pytest.raises(DeliveryError) as exc:
        SecretBox("other-secret-key-0123456789abcdefgh").decrypt(token)
    assert exc.value.retryable is False


def test_signature_format() -> None:
    signature = sign("whsec_x", 1700000000, b'{"a":1}')
    expected = hmac.new(b"whsec_x", b'1700000000.{"a":1}', hashlib.sha256).hexdigest()
    assert signature == f"t=1700000000,v1={expected}"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/x",
        "https://user:pw@example.com/",
        "https://example.com/#x",
        "https://:443/",
        "https://example.com:99999/",
        "https://example.com/" + "a" * 2000,
    ],
)
def test_webhook_url_rejections(url: str) -> None:
    with pytest.raises(ValueError, match=r".+"):
        validate_webhook_url(url, allow_http=True)


def test_webhook_url_scheme_policy() -> None:
    assert validate_webhook_url(" https://hooks.example.com/x?y=1 ", allow_http=False) == (
        "https://hooks.example.com/x?y=1"
    )
    assert validate_webhook_url("http://hooks.example.com/x", allow_http=True)
    with pytest.raises(ValueError, match="https"):
        validate_webhook_url("http://hooks.example.com/x", allow_http=False)


def test_backoff_is_exponential_and_capped() -> None:
    assert [backoff(n) for n in (1, 2, 3)] == [
        timedelta(minutes=1),
        timedelta(minutes=2),
        timedelta(minutes=4),
    ]
    assert backoff(30) == timedelta(hours=6)


def test_smtp_backend_requires_a_host() -> None:
    with pytest.raises(ValidationError, match="smtp_host"):
        _settings(email_backend="smtp")
    assert isinstance(
        build_email_sender(_settings(email_backend="smtp", smtp_host="smtp.example.com")),
        SmtpEmailSender,
    )


def test_webhook_allowed_networks_reject_blocked_ranges() -> None:
    assert _settings(webhook_allowed_networks="10.8.0.0/16").webhook_allowed_networks == [
        "10.8.0.0/16"
    ]
    with pytest.raises(ValidationError):
        _settings(webhook_allowed_networks="127.0.0.0/8")


class FakeSmtp:
    instances: ClassVar[list[FakeSmtp]] = []

    def __init__(self, host: str, port: int, timeout: float, **kwargs: Any) -> None:
        self.host, self.port, self.timeout = host, port, timeout
        self.context = kwargs.get("context")
        self.calls: list[tuple[str, Any]] = []
        FakeSmtp.instances.append(self)

    def __enter__(self) -> FakeSmtp:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.calls.append(("quit", None))

    def starttls(self, context: ssl.SSLContext) -> None:
        self.calls.append(("starttls", context.verify_mode))

    def login(self, username: str, password: str) -> None:
        self.calls.append(("login", (username, password)))

    def send_message(self, message: Any) -> None:
        self.calls.append(("send", message))


async def test_smtp_sender_uses_starttls_and_strips_header_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeSmtp.instances.clear()
    monkeypatch.setattr("app.services.email.smtplib.SMTP", FakeSmtp)
    sender = SmtpEmailSender(
        _settings(
            email_backend="smtp",
            smtp_host="smtp.example.com",
            smtp_username="mailer",
            smtp_password="pw",
        )
    )
    await sender.send(
        EmailMessage(to="soc@example.com", subject="Alert\r\nBcc: evil@example.com", body="hi")
    )
    (client,) = FakeSmtp.instances
    assert (client.host, client.port) == ("smtp.example.com", 587)
    kinds = [c[0] for c in client.calls]
    assert kinds == ["starttls", "login", "send", "quit"]
    assert client.calls[0][1] == ssl.CERT_REQUIRED
    message = client.calls[2][1]
    assert message["Subject"] == "Alert  Bcc: evil@example.com"
    assert message["Bcc"] is None
    assert message["To"] == "soc@example.com"


def _rule(**fields: Any) -> AlertRule:
    values: dict[str, Any] = {
        "event_types": [],
        "min_severity": "medium",
        "asset_id": None,
        "quiet_period_minutes": 0,
    }
    values.update(fields)
    return AlertRule(**values)


def _event(**fields: Any) -> SecurityEvent:
    values: dict[str, Any] = {
        "event_type": "finding.created",
        "severity": "high",
        "asset_id": None,
    }
    values.update(fields)
    return SecurityEvent(**values)


def test_rule_matching() -> None:
    asset = uuid.uuid4()
    assert rule_matches(_rule(), _event())
    assert not rule_matches(_rule(), _event(severity="low"))
    assert rule_matches(_rule(event_types=["finding.created"]), _event())
    assert not rule_matches(_rule(event_types=["scan.failed"]), _event())
    assert not rule_matches(_rule(asset_id=asset), _event(asset_id=uuid.uuid4()))
    assert rule_matches(_rule(asset_id=asset), _event(asset_id=asset))
    assert not rule_matches(_rule(min_severity="info"), _event(event_type="notification.test"))
    assert severity_at_least("critical", "high")
    assert not severity_at_least("info", "low")


async def test_production_refuses_cleartext_webhooks_at_delivery() -> None:
    from types import SimpleNamespace

    from app.services.notifications import Deliverer

    class NoWebhooks:
        async def post(self, *_args: Any) -> Any:
            raise AssertionError("must not be called")

    settings = _settings(
        environment="production",
        log_json=True,
        email_backend="disabled",
        argon2_memory_cost_kib=19456,
        argon2_time_cost=2,
        secret_key="a-real-random-production-secret-0123456789",
    )
    box = SecretBox(settings.secret_key.get_secret_value())
    notification = SimpleNamespace(
        id=uuid.uuid4(),
        channel=SimpleNamespace(
            enabled=True,
            kind="webhook",
            config={"url": "http://hooks.example.com/x"},
            secret_encrypted=box.encrypt("whsec_x"),
        ),
        event=SimpleNamespace(),
    )
    deliverer = Deliverer(settings, build_email_sender(settings), NoWebhooks(), box)  # type: ignore[arg-type]
    with pytest.raises(DeliveryError, match="https") as exc:
        await deliverer.send(notification)  # type: ignore[arg-type]
    assert exc.value.retryable is False
