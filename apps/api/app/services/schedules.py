"""Scheduled scans.

A schedule never bypasses the controls of an interactive scan request: each run
goes through ``ScanService.request`` as the schedule's owner, so membership, the
``scans:execute`` permission, the asset's authorization window and technique,
quotas and the emergency stop are all re-checked at run time. A run that cannot
start is recorded on the schedule (``last_status = "skipped"``) and emitted as a
``schedule.skipped`` event; the schedule then waits for its next slot (no
catch-up bursts after downtime).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.context import Principal, RequestMeta
from app.core.errors import AppError, InvalidRequestError, NotFoundError
from app.core.logging import get_logger
from app.core.permissions import Permission
from app.models import Asset, ScanSchedule, User
from app.schemas.pagination import PageParams
from app.services.audit import record_audit
from app.services.auth import principal_from_user
from app.services.events import EventType, emit
from app.services.projects import ProjectService
from app.services.scan_dispatch import ScanDispatcher
from app.services.scans import ScanService, scanner_class
from sentinelx_security.scope import ScopeEngine

logger = get_logger(__name__)

SCHEDULER_META = RequestMeta(ip_address=None, user_agent="sentinelx-scheduler", request_id=None)
MAX_SCHEDULES_PER_PROJECT = 100


def utcnow() -> datetime:
    return datetime.now(UTC)


class ScheduleService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._projects = ProjectService(session)

    async def list(
        self, principal: Principal, project_id: uuid.UUID, params: PageParams
    ) -> tuple[Sequence[ScanSchedule], int]:
        await self._projects.get(principal, project_id)
        stmt = select(ScanSchedule).where(ScanSchedule.project_id == project_id)
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )
        rows = (
            (
                await self._session.execute(
                    stmt.order_by(ScanSchedule.created_at.desc())
                    .offset(params.offset)
                    .limit(params.page_size)
                )
            )
            .scalars()
            .all()
        )
        return rows, total

    async def get(
        self, principal: Principal, project_id: uuid.UUID, schedule_id: uuid.UUID
    ) -> ScanSchedule:
        await self._projects.get(principal, project_id)
        schedule = (
            await self._session.execute(
                select(ScanSchedule).where(
                    ScanSchedule.id == schedule_id, ScanSchedule.project_id == project_id
                )
            )
        ).scalar_one_or_none()
        if schedule is None:
            raise NotFoundError("Schedule not found.")
        return schedule

    async def create(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        *,
        asset_id: uuid.UUID,
        scanner: str,
        profile: str | None,
        interval_hours: int,
        first_run_at: datetime | None,
        meta: RequestMeta,
    ) -> ScanSchedule:
        await self._projects.get(principal, project_id)
        asset = (
            await self._session.execute(
                select(Asset).where(Asset.id == asset_id, Asset.project_id == project_id)
            )
        ).scalar_one_or_none()
        if asset is None:
            raise NotFoundError("Asset not found.")
        cls = scanner_class(scanner)
        profile = profile or cls.default_profile
        if profile not in cls.profiles:
            raise InvalidRequestError(f"Unknown profile {profile!r} for the {cls.name} scanner.")
        count = int(
            (
                await self._session.execute(
                    select(func.count())
                    .select_from(ScanSchedule)
                    .where(ScanSchedule.project_id == project_id)
                )
            ).scalar_one()
        )
        if count >= MAX_SCHEDULES_PER_PROJECT:
            raise InvalidRequestError(
                f"A project may have at most {MAX_SCHEDULES_PER_PROJECT} schedules."
            )
        now = utcnow()
        schedule = ScanSchedule(
            project_id=project_id,
            asset_id=asset.id,
            scanner=cls.name.value,
            profile=profile,
            interval_hours=interval_hours,
            enabled=True,
            next_run_at=max(first_run_at or now, now),
            owner_id=principal.user_id,
        )
        self._session.add(schedule)
        await self._session.flush()
        record_audit(
            self._session,
            action="scan_schedule.created",
            actor=principal.actor,
            meta=meta,
            target_type="scan_schedule",
            target_id=schedule.id,
            project_id=project_id,
            details=_describe(schedule, asset.value),
        )
        await self._session.commit()
        return await self.get(principal, project_id, schedule.id)

    async def update(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        schedule_id: uuid.UUID,
        changes: dict[str, Any],
        meta: RequestMeta,
    ) -> ScanSchedule:
        schedule = await self.get(principal, project_id, schedule_id)
        if "profile" in changes and changes["profile"] is not None:
            if changes["profile"] not in scanner_class(schedule.scanner).profiles:
                raise InvalidRequestError(f"Unknown profile {changes['profile']!r}.")
            schedule.profile = changes["profile"]
        if changes.get("interval_hours") is not None:
            schedule.interval_hours = int(changes["interval_hours"])
        if changes.get("enabled") is not None:
            enabling = bool(changes["enabled"]) and not schedule.enabled
            schedule.enabled = bool(changes["enabled"])
            if enabling:
                schedule.next_run_at = max(schedule.next_run_at, utcnow())
        if changes.get("next_run_at") is not None:
            schedule.next_run_at = max(changes["next_run_at"], utcnow())
        # Whoever last changed the schedule is accountable for its runs.
        schedule.owner_id = principal.user_id
        record_audit(
            self._session,
            action="scan_schedule.updated",
            actor=principal.actor,
            meta=meta,
            target_type="scan_schedule",
            target_id=schedule.id,
            project_id=project_id,
            details={k: str(v) for k, v in changes.items() if v is not None},
        )
        await self._session.commit()
        return await self.get(principal, project_id, schedule.id)

    async def delete(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        schedule_id: uuid.UUID,
        meta: RequestMeta,
    ) -> None:
        schedule = await self.get(principal, project_id, schedule_id)
        record_audit(
            self._session,
            action="scan_schedule.deleted",
            actor=principal.actor,
            meta=meta,
            target_type="scan_schedule",
            target_id=schedule.id,
            project_id=project_id,
            details=_describe(schedule),
        )
        await self._session.delete(schedule)
        await self._session.commit()


def _describe(schedule: ScanSchedule, target: str | None = None) -> dict[str, Any]:
    details: dict[str, Any] = {
        "asset_id": str(schedule.asset_id),
        "scanner": schedule.scanner,
        "profile": schedule.profile,
        "interval_hours": schedule.interval_hours,
    }
    if target:
        details["target"] = target
    return details


# --------------------------------------------------------------------- worker side


async def _owner_principal(session: AsyncSession, schedule: ScanSchedule) -> Principal:
    user = await session.get(User, schedule.owner_id) if schedule.owner_id else None
    if user is None or not user.is_active:
        raise InvalidRequestError("The schedule's owner no longer has an active account.")
    principal = principal_from_user(user)
    if not principal.has(Permission.SCANS_EXECUTE):
        raise InvalidRequestError("The schedule's owner is no longer allowed to run scans.")
    return principal


async def run_due(
    session: AsyncSession,
    engine: ScopeEngine,
    settings: Settings,
    dispatcher: ScanDispatcher,
    *,
    limit: int = 20,
) -> dict[str, int]:
    """Start every due schedule once. Each schedule is claimed before it runs."""
    now = utcnow()
    due = list(
        (
            await session.execute(
                select(ScanSchedule.id)
                .where(ScanSchedule.enabled.is_(True), ScanSchedule.next_run_at <= now)
                .order_by(ScanSchedule.next_run_at)
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    counts = {"started": 0, "skipped": 0}
    for schedule_id in due:
        schedule = (
            await session.execute(
                select(ScanSchedule)
                .where(
                    ScanSchedule.id == schedule_id,
                    ScanSchedule.enabled.is_(True),
                    ScanSchedule.next_run_at <= now,
                )
                .with_for_update(skip_locked=True)
            )
        ).scalar_one_or_none()
        if schedule is None:
            continue  # another worker claimed it
        # Claim: move to the next slot before running, so a crash never loops.
        schedule.last_run_at = now
        schedule.next_run_at = now + timedelta(hours=schedule.interval_hours)
        await session.commit()

        project_id, asset_id = schedule.project_id, schedule.asset_id
        try:
            principal = await _owner_principal(session, schedule)
            job = await ScanService(session, engine, settings, dispatcher).request(
                principal,
                project_id,
                asset_id=asset_id,
                scanner_name=schedule.scanner,
                profile=schedule.profile,
                meta=SCHEDULER_META,
            )
        except AppError as exc:
            await session.rollback()
            schedule = await session.get(ScanSchedule, schedule_id, populate_existing=True)
            if schedule is None:
                continue
            schedule.last_status = "skipped"
            schedule.last_message = exc.message[:500]
            await emit(
                session,
                project_id=project_id,
                event_type=EventType.SCHEDULE_SKIPPED,
                severity="medium",
                title=f"Scheduled {schedule.scanner}/{schedule.profile} scan skipped",
                asset_id=asset_id,
                details={"schedule_id": str(schedule.id), "reason": exc.message},
                dedup_key=f"schedule.skipped:{schedule.id}",
            )
            await session.commit()
            counts["skipped"] += 1
            logger.info("scan_schedule_skipped", schedule_id=str(schedule_id), reason=exc.code)
            continue
        schedule = await session.get(ScanSchedule, schedule_id, populate_existing=True)
        if schedule is not None:
            schedule.last_status = "started"
            schedule.last_message = None
            schedule.last_scan_job_id = job.id
            await session.commit()
        counts["started"] += 1
    return counts
