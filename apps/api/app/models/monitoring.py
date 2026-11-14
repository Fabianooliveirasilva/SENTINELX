"""Monitoring: security events, alert rules, notification channels and deliveries,
and scheduled scans (Phase 8)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utcnow
from app.models.finding import SEVERITIES

CHANNEL_KINDS = ("email", "webhook")
DELIVERY_STATUSES = ("pending", "sent", "failed", "suppressed")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN (" + ", ".join(repr(v) for v in values) + ")"


class SecurityEvent(UUIDPrimaryKeyMixin, Base):
    """An immutable entry in a project's security timeline."""

    __tablename__ = "security_events"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    event_type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(300))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL")
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    # What "the same thing happening again" means for alert quiet periods.
    dedup_key: Mapped[str] = mapped_column(String(200))
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    actor_email: Mapped[str | None] = mapped_column(String(320))
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )

    __table_args__ = (
        CheckConstraint(_in("severity", SEVERITIES), name="severity"),
        Index("ix_security_events_project_id_occurred_at", "project_id", "occurred_at"),
        Index("ix_security_events_project_id_event_type", "project_id", "event_type"),
        Index("ix_security_events_asset_id", "asset_id"),
    )


alert_rule_channels = Table(
    "alert_rule_channels",
    Base.metadata,
    Column(
        "rule_id",
        ForeignKey("alert_rules.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "channel_id",
        ForeignKey("notification_channels.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Index("ix_alert_rule_channels_channel_id", "channel_id"),
)


class NotificationChannel(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Where alerts are delivered. Webhook signing secrets are stored encrypted."""

    __tablename__ = "notification_channels"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(100))
    kind: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    # email: {"recipients": [...]}; webhook: {"url": "https://..."}
    config: Mapped[dict[str, Any]] = mapped_column(JSONB)
    secret_encrypted: Mapped[str | None] = mapped_column(Text)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        UniqueConstraint("project_id", "name"),
        CheckConstraint(_in("kind", CHANNEL_KINDS), name="kind"),
    )


class AlertRule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Which events notify which channels, with a quiet period against repeats."""

    __tablename__ = "alert_rules"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(100))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    # Empty list = every event type.
    event_types: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)), default=list, server_default=text("'{}'")
    )
    min_severity: Mapped[str] = mapped_column(
        String(16), default="info", server_default=text("'info'")
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    quiet_period_minutes: Mapped[int] = mapped_column(
        Integer, default=60, server_default=text("60")
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    channels: Mapped[list[NotificationChannel]] = relationship(
        secondary=alert_rule_channels, lazy="selectin", order_by=NotificationChannel.name
    )

    __table_args__ = (
        UniqueConstraint("project_id", "name"),
        CheckConstraint(_in("min_severity", SEVERITIES), name="min_severity"),
        CheckConstraint(
            "quiet_period_minutes >= 0 AND quiet_period_minutes <= 10080", name="quiet_period"
        ),
    )


class Notification(UUIDPrimaryKeyMixin, Base):
    """One delivery of one event to one channel (an outbox row)."""

    __tablename__ = "notifications"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    event_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("security_events.id", ondelete="CASCADE")
    )
    rule_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("alert_rules.id", ondelete="SET NULL")
    )
    channel_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("notification_channels.id", ondelete="CASCADE")
    )
    status: Mapped[str] = mapped_column(
        String(16), default="pending", server_default=text("'pending'")
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )
    last_error: Mapped[str | None] = mapped_column(String(300))
    response_status: Mapped[int | None] = mapped_column(Integer)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=text("now()")
    )

    event: Mapped[SecurityEvent] = relationship(lazy="raise")
    channel: Mapped[NotificationChannel] = relationship(lazy="raise")

    __table_args__ = (
        CheckConstraint(_in("status", DELIVERY_STATUSES), name="status"),
        Index("ix_notifications_status_next_attempt_at", "status", "next_attempt_at"),
        Index("ix_notifications_project_id_created_at", "project_id", "created_at"),
        Index("ix_notifications_rule_id_created_at", "rule_id", "created_at"),
    )


class ScanSchedule(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A recurring scan, executed with its owner's authority re-checked every run."""

    __tablename__ = "scan_schedules"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    scanner: Mapped[str] = mapped_column(String(32))
    profile: Mapped[str] = mapped_column(String(32))
    interval_hours: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(32))
    last_message: Mapped[str | None] = mapped_column(String(500))
    last_scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __table_args__ = (
        CheckConstraint("interval_hours >= 1 AND interval_hours <= 2160", name="interval_hours"),
        Index("ix_scan_schedules_enabled_next_run_at", "enabled", "next_run_at"),
        Index("ix_scan_schedules_project_id", "project_id"),
    )
