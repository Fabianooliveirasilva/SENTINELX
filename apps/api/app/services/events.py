"""Security events: the project timeline and the entry point for alerting.

``emit`` is called inside the transaction that caused the event, so an event
exists if and only if the change that produced it was committed. Matching alert
rules turn the event into ``notifications`` rows (an outbox) in the same
transaction; the monitoring worker delivers them afterwards.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AlertRule, Notification, SecurityEvent
from app.models.finding import SEVERITIES

SEVERITY_RANK: Final = {name: rank for rank, name in enumerate(SEVERITIES)}


class EventType(StrEnum):
    FINDING_CREATED = "finding.created"
    FINDING_REOPENED = "finding.reopened"
    FINDING_RESOLVED = "finding.resolved"
    FINDING_STATUS_CHANGED = "finding.status_changed"
    FINDING_RISK_CHANGED = "finding.risk_band_changed"
    FINDING_KEV_LISTED = "finding.kev_listed"
    CERTIFICATE_EXPIRING = "certificate.expiring"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_CANCELLED = "scan.cancelled"
    SCAN_SCOPE_DENIED = "scan.scope_denied"
    SCANNING_HALTED = "scanning.halted"
    SCANNING_RESUMED = "scanning.resumed"
    SCHEDULE_SKIPPED = "schedule.skipped"
    ASSET_CREATED = "asset.created"
    ASSET_UPDATED = "asset.updated"
    AUTHORIZATION_GRANTED = "authorization.granted"
    AUTHORIZATION_REVOKED = "authorization.revoked"
    TEST = "notification.test"


EVENT_DESCRIPTIONS: Final[Mapping[str, str]] = {
    EventType.FINDING_CREATED: "A new finding was observed",
    EventType.FINDING_REOPENED: "A resolved finding was observed again (regression)",
    EventType.FINDING_RESOLVED: "A finding is no longer observed",
    EventType.FINDING_STATUS_CHANGED: "An analyst changed a finding's status",
    EventType.FINDING_RISK_CHANGED: "A finding moved to a different risk band",
    EventType.FINDING_KEV_LISTED: "A finding's CVE was added to the CISA KEV catalog",
    EventType.CERTIFICATE_EXPIRING: "A TLS certificate is expired or expires within 30 days",
    EventType.SCAN_COMPLETED: "A scan completed",
    EventType.SCAN_FAILED: "A scan failed or timed out",
    EventType.SCAN_CANCELLED: "A scan was cancelled",
    EventType.SCAN_SCOPE_DENIED: "The scope engine refused a scan target at execution time",
    EventType.SCANNING_HALTED: "An emergency stop halted all scanning",
    EventType.SCANNING_RESUMED: "Scanning was resumed after an emergency stop",
    EventType.SCHEDULE_SKIPPED: "A scheduled scan could not be started",
    EventType.ASSET_CREATED: "An asset was registered",
    EventType.ASSET_UPDATED: "An asset was modified",
    EventType.AUTHORIZATION_GRANTED: "A scanning authorization was recorded",
    EventType.AUTHORIZATION_REVOKED: "A scanning authorization was revoked",
    EventType.TEST: "A test notification sent from the channel settings",
}

CERTIFICATE_RULES: Final = frozenset({"tls.certificate_expired", "tls.certificate_expiring_soon"})


def utcnow() -> datetime:
    return datetime.now(UTC)


def severity_at_least(severity: str, minimum: str) -> bool:
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(minimum, 0)


async def emit(
    session: AsyncSession,
    *,
    project_id: uuid.UUID,
    event_type: EventType,
    severity: str,
    title: str,
    asset_id: uuid.UUID | None = None,
    finding_id: uuid.UUID | None = None,
    scan_job_id: uuid.UUID | None = None,
    details: Mapping[str, Any] | None = None,
    actor_email: str | None = None,
    dedup_key: str | None = None,
) -> SecurityEvent:
    """Record an event and queue notifications for every matching alert rule."""
    if severity not in SEVERITY_RANK:
        severity = "info"
    subject = finding_id or scan_job_id or asset_id or project_id
    event = SecurityEvent(
        id=uuid.uuid4(),
        project_id=project_id,
        event_type=event_type.value,
        severity=severity,
        title=title[:300],
        asset_id=asset_id,
        finding_id=finding_id,
        scan_job_id=scan_job_id,
        details=dict(details or {}),
        actor_email=actor_email,
        dedup_key=(dedup_key or f"{event_type.value}:{subject}")[:200],
        occurred_at=utcnow(),
    )
    session.add(event)
    await session.flush()
    await _queue_notifications(session, event)
    return event


async def _queue_notifications(session: AsyncSession, event: SecurityEvent) -> None:
    rules = (
        (
            await session.execute(
                select(AlertRule).where(
                    AlertRule.project_id == event.project_id, AlertRule.enabled.is_(True)
                )
            )
        )
        .scalars()
        .all()
    )
    for rule in rules:
        if not rule_matches(rule, event):
            continue
        suppressed = await _in_quiet_period(session, rule, event)
        for channel in rule.channels:
            if not channel.enabled:
                continue
            session.add(
                Notification(
                    project_id=event.project_id,
                    event_id=event.id,
                    rule_id=rule.id,
                    channel_id=channel.id,
                    status="suppressed" if suppressed else "pending",
                    next_attempt_at=event.occurred_at,
                    last_error="Quiet period: an identical alert was sent recently."
                    if suppressed
                    else None,
                )
            )
    await session.flush()


def rule_matches(rule: AlertRule, event: SecurityEvent) -> bool:
    if event.event_type == EventType.TEST:
        return False  # test notifications target one channel directly
    if rule.event_types and event.event_type not in rule.event_types:
        return False
    if rule.asset_id is not None and rule.asset_id != event.asset_id:
        return False
    return severity_at_least(event.severity, rule.min_severity)


async def _in_quiet_period(session: AsyncSession, rule: AlertRule, event: SecurityEvent) -> bool:
    if rule.quiet_period_minutes <= 0:
        return False
    since = event.occurred_at - timedelta(minutes=rule.quiet_period_minutes)
    recent = (
        await session.execute(
            select(Notification.id)
            .join(SecurityEvent, SecurityEvent.id == Notification.event_id)
            .where(
                Notification.rule_id == rule.id,
                Notification.status.in_(("pending", "sent")),
                Notification.created_at >= since,
                SecurityEvent.dedup_key == event.dedup_key,
                SecurityEvent.id != event.id,
            )
            .limit(1)
        )
    ).first()
    return recent is not None
