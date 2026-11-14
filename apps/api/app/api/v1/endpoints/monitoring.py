"""Monitoring: event timeline, alert rules, notification channels, deliveries, schedules."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.core.context import Principal
from app.core.permissions import Permission
from app.dependencies.auth import require_permission
from app.dependencies.core import MonitoringServiceDep, RequestMetaDep, ScheduleServiceDep
from app.models import Notification
from app.schemas.common import error_responses
from app.schemas.monitoring import (
    ChannelCreate,
    ChannelRead,
    ChannelUpdate,
    ChannelWithSecret,
    DeliveryStatus,
    EventSummaryRead,
    EventTypeId,
    EventTypeRead,
    NotificationRead,
    RuleCreate,
    RuleRead,
    RuleUpdate,
    ScheduleCreate,
    ScheduleRead,
    ScheduleUpdate,
    SecurityEventRead,
    Severity,
)
from app.schemas.pagination import Page, PageParams, page_params
from app.services.monitoring import EVENT_CATALOG, EventFilters

router = APIRouter(tags=["monitoring"])

_ERRORS = error_responses(401, 403, 404, 409, 422)
CanReadEvents = Annotated[Principal, Depends(require_permission(Permission.EVENTS_READ))]
CanManageAlerts = Annotated[Principal, Depends(require_permission(Permission.ALERTS_MANAGE))]
CanReadScans = Annotated[Principal, Depends(require_permission(Permission.SCANS_READ))]
CanExecuteScans = Annotated[Principal, Depends(require_permission(Permission.SCANS_EXECUTE))]
Params = Annotated[PageParams, Depends(page_params)]

EVENTS = "/projects/{project_id}/events"
CHANNELS = "/projects/{project_id}/notification-channels"
RULES = "/projects/{project_id}/alert-rules"
SCHEDULES = "/projects/{project_id}/scan-schedules"


# --------------------------------------------------------------------- events


@router.get("/events/types", responses=_ERRORS, summary="Catalog of security event types")
async def event_types(_principal: CanReadEvents) -> list[EventTypeRead]:
    return [EventTypeRead.model_validate(e) for e in EVENT_CATALOG]


@router.get(EVENTS, responses=_ERRORS, summary="Project security event timeline")
async def list_events(
    project_id: uuid.UUID,
    principal: CanReadEvents,
    service: MonitoringServiceDep,
    params: Params,
    event_type: Annotated[list[EventTypeId] | None, Query(max_length=30)] = None,
    min_severity: Severity | None = None,
    asset_id: uuid.UUID | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Page[SecurityEventRead]:
    rows, total = await service.events(
        principal,
        project_id,
        params,
        EventFilters(
            event_types=tuple(event_type or ()),
            min_severity=min_severity,
            asset_id=asset_id,
            since=since,
            until=until,
        ),
    )
    return Page(
        items=[SecurityEventRead.model_validate(r) for r in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )


@router.get(f"{EVENTS}/summary", responses=_ERRORS, summary="Event counts by severity")
async def event_summary(
    project_id: uuid.UUID,
    principal: CanReadEvents,
    service: MonitoringServiceDep,
    days: Annotated[int, Query(ge=1, le=365)] = 7,
) -> EventSummaryRead:
    since = datetime.now(UTC) - timedelta(days=days)
    return EventSummaryRead.model_validate(
        await service.event_summary(principal, project_id, since)
    )


# --------------------------------------------------------------------- channels


@router.get(CHANNELS, responses=_ERRORS, summary="List notification channels")
async def list_channels(
    project_id: uuid.UUID, principal: CanManageAlerts, service: MonitoringServiceDep
) -> list[ChannelRead]:
    return [ChannelRead.of(c) for c in await service.channels(principal, project_id)]


@router.post(
    CHANNELS,
    status_code=status.HTTP_201_CREATED,
    responses=_ERRORS,
    summary="Create a channel (a webhook's signing secret is returned once)",
)
async def create_channel(
    project_id: uuid.UUID,
    payload: ChannelCreate,
    principal: CanManageAlerts,
    service: MonitoringServiceDep,
    meta: RequestMetaDep,
) -> ChannelWithSecret:
    channel, secret = await service.create_channel(
        principal,
        project_id,
        name=payload.name,
        kind=payload.kind,
        recipients=[str(r) for r in payload.recipients] if payload.recipients else None,
        url=payload.url,
        meta=meta,
    )
    return ChannelWithSecret(**ChannelRead.of(channel).model_dump(), signing_secret=secret)


@router.patch(f"{CHANNELS}/{{channel_id}}", responses=_ERRORS, summary="Update a channel")
async def update_channel(
    project_id: uuid.UUID,
    channel_id: uuid.UUID,
    payload: ChannelUpdate,
    principal: CanManageAlerts,
    service: MonitoringServiceDep,
    meta: RequestMetaDep,
) -> ChannelRead:
    changes = payload.model_dump(exclude_unset=True)
    if payload.recipients is not None:
        changes["recipients"] = [str(r) for r in payload.recipients]
    channel = await service.update_channel(principal, project_id, channel_id, changes, meta)
    return ChannelRead.of(channel)


@router.post(
    f"{CHANNELS}/{{channel_id}}/rotate-secret",
    responses=_ERRORS,
    summary="Rotate a webhook signing secret (returned once)",
)
async def rotate_secret(
    project_id: uuid.UUID,
    channel_id: uuid.UUID,
    principal: CanManageAlerts,
    service: MonitoringServiceDep,
    meta: RequestMetaDep,
) -> ChannelWithSecret:
    channel, secret = await service.rotate_secret(principal, project_id, channel_id, meta)
    return ChannelWithSecret(**ChannelRead.of(channel).model_dump(), signing_secret=secret)


@router.post(
    f"{CHANNELS}/{{channel_id}}/test",
    status_code=status.HTTP_202_ACCEPTED,
    responses=_ERRORS,
    summary="Queue a test notification on this channel",
)
async def test_channel(
    project_id: uuid.UUID,
    channel_id: uuid.UUID,
    principal: CanManageAlerts,
    service: MonitoringServiceDep,
    meta: RequestMetaDep,
) -> dict[str, str]:
    notification = await service.test_channel(principal, project_id, channel_id, meta)
    return {"notification_id": str(notification.id), "status": notification.status}


@router.delete(
    f"{CHANNELS}/{{channel_id}}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=_ERRORS,
    summary="Delete a channel",
)
async def delete_channel(
    project_id: uuid.UUID,
    channel_id: uuid.UUID,
    principal: CanManageAlerts,
    service: MonitoringServiceDep,
    meta: RequestMetaDep,
) -> None:
    await service.delete_channel(principal, project_id, channel_id, meta)


# --------------------------------------------------------------------- rules


@router.get(RULES, responses=_ERRORS, summary="List alert rules")
async def list_rules(
    project_id: uuid.UUID, principal: CanReadEvents, service: MonitoringServiceDep
) -> list[RuleRead]:
    return [RuleRead.of(r) for r in await service.rules(principal, project_id)]


@router.post(RULES, status_code=status.HTTP_201_CREATED, responses=_ERRORS, summary="Create a rule")
async def create_rule(
    project_id: uuid.UUID,
    payload: RuleCreate,
    principal: CanManageAlerts,
    service: MonitoringServiceDep,
    meta: RequestMetaDep,
) -> RuleRead:
    rule = await service.create_rule(principal, project_id, payload.model_dump(), meta)
    return RuleRead.of(rule)


@router.patch(f"{RULES}/{{rule_id}}", responses=_ERRORS, summary="Update an alert rule")
async def update_rule(
    project_id: uuid.UUID,
    rule_id: uuid.UUID,
    payload: RuleUpdate,
    principal: CanManageAlerts,
    service: MonitoringServiceDep,
    meta: RequestMetaDep,
) -> RuleRead:
    rule = await service.update_rule(
        principal, project_id, rule_id, payload.model_dump(exclude_unset=True), meta
    )
    return RuleRead.of(rule)


@router.delete(
    f"{RULES}/{{rule_id}}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=_ERRORS,
    summary="Delete an alert rule",
)
async def delete_rule(
    project_id: uuid.UUID,
    rule_id: uuid.UUID,
    principal: CanManageAlerts,
    service: MonitoringServiceDep,
    meta: RequestMetaDep,
) -> None:
    await service.delete_rule(principal, project_id, rule_id, meta)


# --------------------------------------------------------------------- deliveries


def _delivery(n: Notification) -> NotificationRead:
    return NotificationRead(
        id=n.id,
        status=n.status,  # type: ignore[arg-type]
        attempts=n.attempts,
        last_error=n.last_error,
        response_status=n.response_status,
        next_attempt_at=n.next_attempt_at,
        sent_at=n.sent_at,
        created_at=n.created_at,
        rule_id=n.rule_id,
        channel_id=n.channel_id,
        channel_name=n.channel.name,
        channel_kind=n.channel.kind,  # type: ignore[arg-type]
        event_id=n.event_id,
        event_type=n.event.event_type,
        event_title=n.event.title,
        event_severity=n.event.severity,  # type: ignore[arg-type]
    )


@router.get(
    "/projects/{project_id}/notifications", responses=_ERRORS, summary="Notification delivery log"
)
async def list_notifications(
    project_id: uuid.UUID,
    principal: CanManageAlerts,
    service: MonitoringServiceDep,
    params: Params,
    status_filter: Annotated[DeliveryStatus | None, Query(alias="status")] = None,
) -> Page[NotificationRead]:
    rows, total = await service.notifications(principal, project_id, params, status_filter)
    return Page(
        items=[_delivery(n) for n in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )


# --------------------------------------------------------------------- schedules


@router.get(SCHEDULES, responses=_ERRORS, summary="List scan schedules")
async def list_schedules(
    project_id: uuid.UUID, principal: CanReadScans, service: ScheduleServiceDep, params: Params
) -> Page[ScheduleRead]:
    rows, total = await service.list(principal, project_id, params)
    return Page(
        items=[ScheduleRead.model_validate(r) for r in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )


@router.post(
    SCHEDULES,
    status_code=status.HTTP_201_CREATED,
    responses=_ERRORS,
    summary="Schedule a recurring scan (runs with your authority, re-checked every run)",
)
async def create_schedule(
    project_id: uuid.UUID,
    payload: ScheduleCreate,
    principal: CanExecuteScans,
    service: ScheduleServiceDep,
    meta: RequestMetaDep,
) -> ScheduleRead:
    schedule = await service.create(
        principal,
        project_id,
        asset_id=payload.asset_id,
        scanner=payload.scanner,
        profile=payload.profile,
        interval_hours=payload.interval_hours,
        first_run_at=payload.first_run_at,
        meta=meta,
    )
    return ScheduleRead.model_validate(schedule)


@router.patch(f"{SCHEDULES}/{{schedule_id}}", responses=_ERRORS, summary="Update a schedule")
async def update_schedule(
    project_id: uuid.UUID,
    schedule_id: uuid.UUID,
    payload: ScheduleUpdate,
    principal: CanExecuteScans,
    service: ScheduleServiceDep,
    meta: RequestMetaDep,
) -> ScheduleRead:
    schedule = await service.update(
        principal, project_id, schedule_id, payload.model_dump(exclude_unset=True), meta
    )
    return ScheduleRead.model_validate(schedule)


@router.delete(
    f"{SCHEDULES}/{{schedule_id}}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=_ERRORS,
    summary="Delete a schedule",
)
async def delete_schedule(
    project_id: uuid.UUID,
    schedule_id: uuid.UUID,
    principal: CanExecuteScans,
    service: ScheduleServiceDep,
    meta: RequestMetaDep,
) -> None:
    await service.delete(principal, project_id, schedule_id, meta)
