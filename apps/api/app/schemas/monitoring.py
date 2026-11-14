"""Monitoring schemas: events, alert rules, notification channels, deliveries, schedules.

Event titles and details can contain scanner-derived text (untrusted): the API
returns them as plain JSON and the UI renders them as text only.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints

from app.models import AlertRule, NotificationChannel

Severity = Literal["info", "low", "medium", "high", "critical"]
ChannelKind = Literal["email", "webhook"]
DeliveryStatus = Literal["pending", "sent", "failed", "suppressed"]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=100)]
EventTypeId = Annotated[str, StringConstraints(pattern=r"^[a-z_]{2,32}\.[a-z_]{2,32}$")]


# --------------------------------------------------------------------- events


class SecurityEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    event_type: str
    severity: Severity
    title: str
    asset_id: uuid.UUID | None
    finding_id: uuid.UUID | None
    scan_job_id: uuid.UUID | None
    details: dict[str, Any]
    actor_email: str | None
    occurred_at: datetime


class EventTypeRead(BaseModel):
    type: str
    description: str


class EventSummaryRead(BaseModel):
    since: datetime
    total: int
    by_severity: dict[str, int]


# --------------------------------------------------------------------- channels


class ChannelCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Name
    kind: ChannelKind
    recipients: list[EmailStr] | None = Field(default=None, max_length=20)
    url: str | None = Field(default=None, max_length=2000)


class ChannelUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Name | None = None
    enabled: bool | None = None
    recipients: list[EmailStr] | None = Field(default=None, max_length=20)
    url: str | None = Field(default=None, max_length=2000)


class ChannelRead(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    kind: ChannelKind
    enabled: bool
    recipients: list[str] | None
    url: str | None
    has_secret: bool
    created_at: datetime
    updated_at: datetime

    @classmethod
    def of(cls, channel: NotificationChannel) -> ChannelRead:
        return cls(
            id=channel.id,
            project_id=channel.project_id,
            name=channel.name,
            kind=channel.kind,  # type: ignore[arg-type]
            enabled=channel.enabled,
            recipients=channel.config.get("recipients"),
            url=channel.config.get("url"),
            has_secret=channel.secret_encrypted is not None,
            created_at=channel.created_at,
            updated_at=channel.updated_at,
        )


class ChannelWithSecret(ChannelRead):
    signing_secret: str | None = Field(
        description="Shown only once, when the channel is created or the secret rotated."
    )


# --------------------------------------------------------------------- rules


class RuleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Name
    enabled: bool = True
    event_types: list[EventTypeId] = Field(default_factory=list, max_length=50)
    min_severity: Severity = "medium"
    asset_id: uuid.UUID | None = None
    quiet_period_minutes: int = Field(default=60, ge=0, le=10080)
    channel_ids: list[uuid.UUID] = Field(min_length=1, max_length=20)


class RuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Name | None = None
    enabled: bool | None = None
    event_types: list[EventTypeId] | None = Field(default=None, max_length=50)
    min_severity: Severity | None = None
    asset_id: uuid.UUID | None = None
    quiet_period_minutes: int | None = Field(default=None, ge=0, le=10080)
    channel_ids: list[uuid.UUID] | None = Field(default=None, min_length=1, max_length=20)


class RuleChannelRead(BaseModel):
    id: uuid.UUID
    name: str
    kind: ChannelKind
    enabled: bool


class RuleRead(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    enabled: bool
    event_types: list[str]
    min_severity: Severity
    asset_id: uuid.UUID | None
    quiet_period_minutes: int
    channels: list[RuleChannelRead]
    created_at: datetime
    updated_at: datetime

    @classmethod
    def of(cls, rule: AlertRule) -> RuleRead:
        return cls(
            id=rule.id,
            project_id=rule.project_id,
            name=rule.name,
            enabled=rule.enabled,
            event_types=list(rule.event_types),
            min_severity=rule.min_severity,  # type: ignore[arg-type]
            asset_id=rule.asset_id,
            quiet_period_minutes=rule.quiet_period_minutes,
            channels=[
                RuleChannelRead(id=c.id, name=c.name, kind=c.kind, enabled=c.enabled)  # type: ignore[arg-type]
                for c in rule.channels
            ],
            created_at=rule.created_at,
            updated_at=rule.updated_at,
        )


# --------------------------------------------------------------------- deliveries


class NotificationRead(BaseModel):
    id: uuid.UUID
    status: DeliveryStatus
    attempts: int
    last_error: str | None
    response_status: int | None
    next_attempt_at: datetime
    sent_at: datetime | None
    created_at: datetime
    rule_id: uuid.UUID | None
    channel_id: uuid.UUID
    channel_name: str
    channel_kind: ChannelKind
    event_id: uuid.UUID
    event_type: str
    event_title: str
    event_severity: Severity


# --------------------------------------------------------------------- schedules


class ScheduleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: uuid.UUID
    scanner: Annotated[str, StringConstraints(pattern=r"^[a-z]{2,32}$")]
    profile: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{1,32}$")] | None = None
    interval_hours: int = Field(ge=1, le=2160)
    first_run_at: datetime | None = None


class ScheduleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{1,32}$")] | None = None
    interval_hours: int | None = Field(default=None, ge=1, le=2160)
    enabled: bool | None = None
    next_run_at: datetime | None = None


class ScheduleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    asset_id: uuid.UUID
    scanner: str
    profile: str
    interval_hours: int
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    last_status: str | None
    last_message: str | None
    last_scan_job_id: uuid.UUID | None
    owner_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
