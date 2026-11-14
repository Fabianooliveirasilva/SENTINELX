"""API-side monitoring: event timeline queries, alert rules and notification channels."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.core.context import Principal, RequestMeta
from app.core.errors import ConflictError, InvalidRequestError, NotFoundError
from app.models import AlertRule, Asset, Notification, NotificationChannel, SecurityEvent
from app.models.finding import SEVERITIES
from app.schemas.pagination import PageParams
from app.services.audit import record_audit
from app.services.events import EVENT_DESCRIPTIONS, SEVERITY_RANK, EventType, emit
from app.services.notifications import (
    SecretBox,
    new_signing_secret,
    queue_test,
    validate_webhook_url,
)
from app.services.projects import ProjectService

MAX_CHANNELS_PER_PROJECT = 20
MAX_RULES_PER_PROJECT = 50
MAX_RECIPIENTS = 20


@dataclass(frozen=True, slots=True)
class EventFilters:
    event_types: tuple[str, ...] = ()
    min_severity: str | None = None
    asset_id: uuid.UUID | None = None
    since: datetime | None = None
    until: datetime | None = None


async def _count(session: AsyncSession, stmt: Any) -> int:
    return int(
        (await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    )


class MonitoringService:
    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self._session = session
        self._settings = settings
        self._projects = ProjectService(session)

    # ------------------------------------------------------------------ events

    async def events(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        params: PageParams,
        filters: EventFilters,
    ) -> tuple[Sequence[SecurityEvent], int]:
        await self._projects.get(principal, project_id)
        stmt = select(SecurityEvent).where(SecurityEvent.project_id == project_id)
        if filters.event_types:
            stmt = stmt.where(SecurityEvent.event_type.in_(filters.event_types))
        if filters.min_severity:
            allowed = [
                s for s in SEVERITIES if SEVERITY_RANK[s] >= SEVERITY_RANK[filters.min_severity]
            ]
            stmt = stmt.where(SecurityEvent.severity.in_(allowed))
        if filters.asset_id:
            stmt = stmt.where(SecurityEvent.asset_id == filters.asset_id)
        if filters.since:
            stmt = stmt.where(SecurityEvent.occurred_at >= filters.since)
        if filters.until:
            stmt = stmt.where(SecurityEvent.occurred_at < filters.until)
        total = await _count(self._session, stmt)
        rows = (
            (
                await self._session.execute(
                    stmt.order_by(SecurityEvent.occurred_at.desc(), SecurityEvent.id)
                    .offset(params.offset)
                    .limit(params.page_size)
                )
            )
            .scalars()
            .all()
        )
        return rows, total

    async def event_summary(
        self, principal: Principal, project_id: uuid.UUID, since: datetime
    ) -> dict[str, Any]:
        await self._projects.get(principal, project_id)
        rows = (
            await self._session.execute(
                select(SecurityEvent.severity, func.count())
                .where(SecurityEvent.project_id == project_id, SecurityEvent.occurred_at >= since)
                .group_by(SecurityEvent.severity)
            )
        ).all()
        counts = dict.fromkeys(SEVERITIES, 0)
        counts.update({severity: int(n) for severity, n in rows})
        return {"since": since, "by_severity": counts, "total": sum(counts.values())}

    # ------------------------------------------------------------------ channels

    async def channels(
        self, principal: Principal, project_id: uuid.UUID
    ) -> Sequence[NotificationChannel]:
        await self._projects.get(principal, project_id)
        return (
            (
                await self._session.execute(
                    select(NotificationChannel)
                    .where(NotificationChannel.project_id == project_id)
                    .order_by(NotificationChannel.name)
                )
            )
            .scalars()
            .all()
        )

    async def channel(
        self, principal: Principal, project_id: uuid.UUID, channel_id: uuid.UUID
    ) -> NotificationChannel:
        await self._projects.get(principal, project_id)
        channel = (
            await self._session.execute(
                select(NotificationChannel).where(
                    NotificationChannel.id == channel_id,
                    NotificationChannel.project_id == project_id,
                )
            )
        ).scalar_one_or_none()
        if channel is None:
            raise NotFoundError("Notification channel not found.")
        return channel

    def _config(
        self, kind: str, recipients: Sequence[str] | None, url: str | None
    ) -> dict[str, Any]:
        if kind == "email":
            unique = sorted({r.strip().lower() for r in recipients or [] if r.strip()})
            if not unique:
                raise InvalidRequestError("An e-mail channel needs at least one recipient.")
            if len(unique) > MAX_RECIPIENTS:
                raise InvalidRequestError(f"At most {MAX_RECIPIENTS} recipients are allowed.")
            return {"recipients": unique}
        if not url:
            raise InvalidRequestError("A webhook channel needs a URL.")
        try:
            return {"url": validate_webhook_url(url, allow_http=not self._settings.is_production)}
        except ValueError as exc:
            raise InvalidRequestError(str(exc)) from exc

    async def create_channel(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        *,
        name: str,
        kind: str,
        recipients: Sequence[str] | None,
        url: str | None,
        meta: RequestMeta,
    ) -> tuple[NotificationChannel, str | None]:
        await self._projects.get(principal, project_id)
        existing = await _count(
            self._session,
            select(NotificationChannel.id).where(NotificationChannel.project_id == project_id),
        )
        if existing >= MAX_CHANNELS_PER_PROJECT:
            raise InvalidRequestError(
                f"A project may have at most {MAX_CHANNELS_PER_PROJECT} channels."
            )
        secret = new_signing_secret() if kind == "webhook" else None
        channel = NotificationChannel(
            project_id=project_id,
            name=name.strip(),
            kind=kind,
            enabled=True,
            config=self._config(kind, recipients, url),
            secret_encrypted=self._box().encrypt(secret) if secret else None,
            created_by_id=principal.user_id,
        )
        self._session.add(channel)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise ConflictError("A channel with this name already exists.") from exc
        record_audit(
            self._session,
            action="notification_channel.created",
            actor=principal.actor,
            meta=meta,
            target_type="notification_channel",
            target_id=channel.id,
            project_id=project_id,
            details={"name": channel.name, "kind": kind, **_safe_config(channel)},
        )
        await self._session.commit()
        return await self.channel(principal, project_id, channel.id), secret

    async def update_channel(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        channel_id: uuid.UUID,
        changes: dict[str, Any],
        meta: RequestMeta,
    ) -> NotificationChannel:
        channel = await self.channel(principal, project_id, channel_id)
        if changes.get("name") is not None:
            channel.name = str(changes["name"]).strip()
        if changes.get("enabled") is not None:
            channel.enabled = bool(changes["enabled"])
        if changes.get("recipients") is not None or changes.get("url") is not None:
            channel.config = self._config(
                channel.kind, changes.get("recipients"), changes.get("url")
            )
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise ConflictError("A channel with this name already exists.") from exc
        record_audit(
            self._session,
            action="notification_channel.updated",
            actor=principal.actor,
            meta=meta,
            target_type="notification_channel",
            target_id=channel.id,
            project_id=project_id,
            details={"name": channel.name, "enabled": channel.enabled, **_safe_config(channel)},
        )
        await self._session.commit()
        return await self.channel(principal, project_id, channel.id)

    async def rotate_secret(
        self, principal: Principal, project_id: uuid.UUID, channel_id: uuid.UUID, meta: RequestMeta
    ) -> tuple[NotificationChannel, str]:
        channel = await self.channel(principal, project_id, channel_id)
        if channel.kind != "webhook":
            raise InvalidRequestError("Only webhook channels have a signing secret.")
        secret = new_signing_secret()
        channel.secret_encrypted = self._box().encrypt(secret)
        record_audit(
            self._session,
            action="notification_channel.secret_rotated",
            actor=principal.actor,
            meta=meta,
            target_type="notification_channel",
            target_id=channel.id,
            project_id=project_id,
        )
        await self._session.commit()
        return await self.channel(principal, project_id, channel.id), secret

    async def delete_channel(
        self, principal: Principal, project_id: uuid.UUID, channel_id: uuid.UUID, meta: RequestMeta
    ) -> None:
        channel = await self.channel(principal, project_id, channel_id)
        record_audit(
            self._session,
            action="notification_channel.deleted",
            actor=principal.actor,
            meta=meta,
            target_type="notification_channel",
            target_id=channel.id,
            project_id=project_id,
            details={"name": channel.name, "kind": channel.kind},
        )
        await self._session.delete(channel)
        await self._session.commit()

    async def test_channel(
        self, principal: Principal, project_id: uuid.UUID, channel_id: uuid.UUID, meta: RequestMeta
    ) -> Notification:
        channel = await self.channel(principal, project_id, channel_id)
        if not channel.enabled:
            raise ConflictError("Enable the channel before testing it.")
        event = await emit(
            self._session,
            project_id=project_id,
            event_type=EventType.TEST,
            severity="info",
            title=f"Test notification for channel {channel.name!r}",
            details={"channel_id": str(channel.id)},
            actor_email=principal.email,
            dedup_key=f"notification.test:{uuid.uuid4()}",
        )
        notification = await queue_test(self._session, channel, event)
        record_audit(
            self._session,
            action="notification_channel.tested",
            actor=principal.actor,
            meta=meta,
            target_type="notification_channel",
            target_id=channel.id,
            project_id=project_id,
        )
        await self._session.commit()
        return notification

    def _box(self) -> SecretBox:
        return SecretBox(self._settings.secret_key.get_secret_value())

    # ------------------------------------------------------------------ rules

    async def rules(self, principal: Principal, project_id: uuid.UUID) -> Sequence[AlertRule]:
        await self._projects.get(principal, project_id)
        return (
            (
                await self._session.execute(
                    select(AlertRule)
                    .where(AlertRule.project_id == project_id)
                    .order_by(AlertRule.name)
                )
            )
            .scalars()
            .all()
        )

    async def rule(
        self, principal: Principal, project_id: uuid.UUID, rule_id: uuid.UUID
    ) -> AlertRule:
        await self._projects.get(principal, project_id)
        rule = (
            await self._session.execute(
                select(AlertRule)
                .where(AlertRule.id == rule_id, AlertRule.project_id == project_id)
                .execution_options(populate_existing=True)
                .options(selectinload(AlertRule.channels))
            )
        ).scalar_one_or_none()
        if rule is None:
            raise NotFoundError("Alert rule not found.")
        return rule

    async def _rule_fields(self, project_id: uuid.UUID, data: dict[str, Any]) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if data.get("event_types") is not None:
            unknown = set(data["event_types"]) - {
                e.value for e in EventType if e is not EventType.TEST
            }
            if unknown:
                raise InvalidRequestError(f"Unknown event types: {', '.join(sorted(unknown))}.")
            fields["event_types"] = sorted(set(data["event_types"]))
        if data.get("min_severity") is not None:
            fields["min_severity"] = data["min_severity"]
        if "asset_id" in data:
            asset_id = data["asset_id"]
            if asset_id is not None:
                asset = await self._session.get(Asset, asset_id)
                if asset is None or asset.project_id != project_id:
                    raise NotFoundError("Asset not found.")
            fields["asset_id"] = asset_id
        if data.get("quiet_period_minutes") is not None:
            fields["quiet_period_minutes"] = int(data["quiet_period_minutes"])
        if data.get("enabled") is not None:
            fields["enabled"] = bool(data["enabled"])
        if data.get("name") is not None:
            fields["name"] = str(data["name"]).strip()
        if data.get("channel_ids") is not None:
            ids = set(data["channel_ids"])
            channels = (
                (
                    await self._session.execute(
                        select(NotificationChannel).where(
                            NotificationChannel.id.in_(ids),
                            NotificationChannel.project_id == project_id,
                        )
                    )
                )
                .scalars()
                .all()
            )
            if len(channels) != len(ids):
                raise NotFoundError("Notification channel not found.")
            fields["channels"] = list(channels)
        return fields

    async def create_rule(
        self, principal: Principal, project_id: uuid.UUID, data: dict[str, Any], meta: RequestMeta
    ) -> AlertRule:
        await self._projects.get(principal, project_id)
        existing = await _count(
            self._session, select(AlertRule.id).where(AlertRule.project_id == project_id)
        )
        if existing >= MAX_RULES_PER_PROJECT:
            raise InvalidRequestError(
                f"A project may have at most {MAX_RULES_PER_PROJECT} alert rules."
            )
        fields = await self._rule_fields(project_id, data)
        if not fields.get("channels"):
            raise InvalidRequestError("An alert rule needs at least one channel.")
        rule = AlertRule(project_id=project_id, created_by_id=principal.user_id, **fields)
        self._session.add(rule)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise ConflictError("An alert rule with this name already exists.") from exc
        record_audit(
            self._session,
            action="alert_rule.created",
            actor=principal.actor,
            meta=meta,
            target_type="alert_rule",
            target_id=rule.id,
            project_id=project_id,
            details=_describe_rule(rule),
        )
        await self._session.commit()
        return await self.rule(principal, project_id, rule.id)

    async def update_rule(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        rule_id: uuid.UUID,
        data: dict[str, Any],
        meta: RequestMeta,
    ) -> AlertRule:
        rule = await self.rule(principal, project_id, rule_id)
        fields = await self._rule_fields(project_id, data)
        if "channels" in fields and not fields["channels"]:
            raise InvalidRequestError("An alert rule needs at least one channel.")
        for name, value in fields.items():
            setattr(rule, name, value)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise ConflictError("An alert rule with this name already exists.") from exc
        record_audit(
            self._session,
            action="alert_rule.updated",
            actor=principal.actor,
            meta=meta,
            target_type="alert_rule",
            target_id=rule.id,
            project_id=project_id,
            details=_describe_rule(rule),
        )
        await self._session.commit()
        return await self.rule(principal, project_id, rule.id)

    async def delete_rule(
        self, principal: Principal, project_id: uuid.UUID, rule_id: uuid.UUID, meta: RequestMeta
    ) -> None:
        rule = await self.rule(principal, project_id, rule_id)
        record_audit(
            self._session,
            action="alert_rule.deleted",
            actor=principal.actor,
            meta=meta,
            target_type="alert_rule",
            target_id=rule.id,
            project_id=project_id,
            details={"name": rule.name},
        )
        await self._session.delete(rule)
        await self._session.commit()

    # ------------------------------------------------------------------ deliveries

    async def notifications(
        self, principal: Principal, project_id: uuid.UUID, params: PageParams, status: str | None
    ) -> tuple[Sequence[Notification], int]:
        await self._projects.get(principal, project_id)
        stmt = select(Notification).where(Notification.project_id == project_id)
        if status:
            stmt = stmt.where(Notification.status == status)
        total = await _count(self._session, stmt)
        rows = (
            (
                await self._session.execute(
                    stmt.options(
                        selectinload(Notification.event), selectinload(Notification.channel)
                    )
                    .order_by(Notification.created_at.desc(), Notification.id)
                    .offset(params.offset)
                    .limit(params.page_size)
                )
            )
            .scalars()
            .all()
        )
        return rows, total


def _safe_config(channel: NotificationChannel) -> dict[str, Any]:
    """Configuration for audit records: the webhook host only (paths may hold tokens)."""
    if channel.kind == "email":
        return {"recipients": len(channel.config.get("recipients", []))}
    return {"host": urlsplit(str(channel.config.get("url", ""))).hostname}


def _describe_rule(rule: AlertRule) -> dict[str, Any]:
    return {
        "name": rule.name,
        "enabled": rule.enabled,
        "event_types": list(rule.event_types),
        "min_severity": rule.min_severity,
        "asset_id": str(rule.asset_id) if rule.asset_id else None,
        "quiet_period_minutes": rule.quiet_period_minutes,
        "channels": [str(c.id) for c in rule.channels],
    }


EVENT_CATALOG = [
    {"type": e.value, "description": EVENT_DESCRIPTIONS[e.value]}
    for e in EventType
    if e is not EventType.TEST
]
