"""Scan orchestration: request, quota, cancel, emergency stop and lifecycle.

The API performs a *preflight* (static) scope check so obviously invalid
requests fail fast; the authoritative check — with fresh DNS resolution and
address pinning — runs again inside the scanner sandbox at execution time.

Job states: ``pending → queued → running → completed | failed | cancelled``.
State lives in PostgreSQL; Redis only carries messages, so losing the broker
never loses the record of a scan. Jobs whose messages are lost are expired by
``expire_stale_jobs`` (called on every request and by a periodic task).
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import Settings
from app.core.context import Actor, Principal, RequestMeta
from app.core.errors import (
    ConflictError,
    InvalidRequestError,
    NotFoundError,
    QuotaExceededError,
    ServiceUnavailableError,
)
from app.core.logging import get_logger
from app.models import Asset, PlatformSetting, Project, ScanEvidence, ScanJob, ScanResult
from app.models.platform import SCANS_HALTED_KEY
from app.models.scan import ACTIVE_STATUSES
from app.schemas.pagination import PageParams
from app.services.assets import compute_eligibility, to_scope_asset
from app.services.audit import record_audit
from app.services.findings import ingest_findings
from app.services.intel import correlate_asset, record_components
from app.services.projects import ProjectService
from app.services.risk import snapshot
from app.services.scan_dispatch import ScanDispatcher
from sentinelx_security.scanners import CATALOG, ScannerName, ScanRequest
from sentinelx_security.scanners.base import ScanError, Scanner
from sentinelx_security.scope import AssetType, ScopeEngine, Technique
from sentinelx_security.scope.serialization import asset_to_dict

logger = get_logger(__name__)

SYSTEM_ACTOR: Final = Actor(id=None, email="system")
SYSTEM_META: Final = RequestMeta(ip_address=None, user_agent="sentinelx-worker", request_id=None)
# Allowance for broker latency and result persistence beyond the scan timeout.
RUNNING_GRACE_SECONDS: Final = 120
MAX_EVIDENCE_ITEMS: Final = 50


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ScanControls:
    halted: bool
    reason: str | None
    updated_at: datetime | None
    updated_by: str | None


@dataclass(frozen=True, slots=True)
class ScanFilters:
    status: str | None = None
    asset_id: uuid.UUID | None = None
    scanner: str | None = None


def scanner_class(name: str) -> type[Scanner]:
    try:
        return CATALOG[ScannerName(name)]
    except ValueError as exc:
        raise InvalidRequestError(f"Unknown scanner {name!r}.") from exc


# --------------------------------------------------------------------- lifecycle helpers


async def get_controls(session: AsyncSession) -> ScanControls:
    setting = await session.get(PlatformSetting, SCANS_HALTED_KEY)
    if setting is None or not setting.value.get("halted"):
        return ScanControls(False, None, setting.updated_at if setting else None, None)
    return ScanControls(
        True,
        setting.value.get("reason"),
        setting.updated_at,
        setting.value.get("by"),
    )


async def expire_stale_jobs(session: AsyncSession, settings: Settings) -> int:
    """Fail jobs whose messages were lost (broker restart, crashed sandbox)."""
    now = utcnow()
    queue_cutoff = now - timedelta(seconds=settings.scan_queue_timeout_seconds)
    run_cutoff = now - timedelta(seconds=settings.max_scan_timeout_seconds + RUNNING_GRACE_SECONDS)
    expired = 0
    for status, column, cutoff, code, message in (
        ("pending", ScanJob.created_at, queue_cutoff, "dispatch_lost", "The job was never queued."),
        (
            "queued",
            ScanJob.queued_at,
            queue_cutoff,
            "queue_timeout",
            "No scanner worker picked up the job in time.",
        ),
        (
            "running",
            ScanJob.started_at,
            run_cutoff,
            "execution_lost",
            "The scanner did not report a result in time.",
        ),
    ):
        result = await session.execute(
            update(ScanJob)
            .where(ScanJob.status == status, column < cutoff)
            .values(status="failed", finished_at=now, error_code=code, error_message=message)
            .returning(ScanJob.id)
        )
        expired += len(result.all())
    if expired:
        logger.warning("scan_jobs_expired", count=expired)
    return expired


def _summary(observations: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    kinds = Counter(str(o["kind"]) for o in observations)
    attention = Counter(flag for o in observations for flag in o.get("attention", []))
    return {
        "observations": len(observations),
        "by_kind": dict(sorted(kinds.items())),
        "attention": dict(attention.most_common()),
    }


# --------------------------------------------------------------------- worker-side steps


async def start_job(
    session: AsyncSession, job_id: uuid.UUID, settings: Settings
) -> dict[str, Any] | None:
    """Mark the job running and build the scanner request (or ``None`` to skip)."""
    job = (
        await session.execute(select(ScanJob).where(ScanJob.id == job_id).with_for_update())
    ).scalar_one_or_none()
    if job is None or job.status != "queued":
        return None
    controls = await get_controls(session)
    if controls.halted:
        _cancel(job, "emergency_stop", "Scanning is halted by an emergency stop.")
        await session.commit()
        return None
    assets = (
        (await session.execute(select(Asset).where(Asset.project_id == job.project_id)))
        .scalars()
        .all()
    )
    job.status = "running"
    job.started_at = utcnow()
    request = ScanRequest(
        job_id=str(job.id),
        scanner=ScannerName(job.scanner),
        profile=job.profile,
        target=job.target,
        assets=[asset_to_dict(to_scope_asset(a)) for a in assets],
        timeout_seconds=float(settings.scan_timeout_for(job.scanner)),
    )
    await session.commit()
    return request.to_dict()


async def record_outcome(
    session: AsyncSession, job_id: uuid.UUID, outcome: Mapping[str, Any] | None
) -> str | None:
    """Persist a scanner outcome. Returns the final status, or ``None`` if ignored."""
    job = (
        await session.execute(select(ScanJob).where(ScanJob.id == job_id).with_for_update())
    ).scalar_one_or_none()
    # Cancelled or expired jobs keep their state; late results are discarded.
    if job is None or job.status != "running" or outcome is None:
        return None
    observations: list[dict[str, Any]] = list(outcome.get("observations") or [])
    decision = outcome.get("decision")
    job.scope_decision = decision
    job.pinned_addresses = [
        a["address"] for a in (decision or {}).get("addresses", []) if a.get("allowed")
    ]
    job.tool_versions = dict(outcome.get("tool_versions") or {})
    job.finished_at = utcnow()
    if outcome.get("status") == "completed":
        job.status = "completed"
        job.summary = _summary(observations)
        session.add_all(
            ScanResult(
                scan_job_id=job.id,
                project_id=job.project_id,
                kind=str(o["kind"])[:64],
                key=str(o["key"])[:512],
                data=dict(o.get("data") or {}),
                attention=[str(a)[:64] for a in o.get("attention", [])],
            )
            for o in observations
        )
        session.add_all(
            ScanEvidence(
                scan_job_id=job.id,
                label=str(e["label"])[:200],
                media_type=str(e.get("media_type", "text/plain"))[:100],
                content=str(e["content"]),
            )
            for e in list(outcome.get("evidence") or [])[:MAX_EVIDENCE_ITEMS]
        )
        await session.flush()
        ingested = await ingest_findings(session, job, observations)
        components = await record_components(session, job, observations)
        # Correlate with the CVEs already stored; the intel worker refreshes stale
        # products from NVD afterwards and re-correlates.
        cves = await correlate_asset(session, job.project_id, job.asset_id, job.scanner, job.id)
        job.summary = {
            **job.summary,
            "findings": ingested.to_dict(),
            "software": len(components),
            "cve_findings": cves.to_dict(),
        }
        await snapshot(session, job.project_id)
    else:
        job.status = "failed"
        job.error_code = str(outcome.get("error_code") or "scanner_error")[:64]
        job.error_message = str(outcome.get("error_message") or "The scan failed.")
    denied = outcome.get("status") == "denied"
    record_audit(
        session,
        action="scan.scope_denied" if denied else f"scan.{job.status}",
        actor=SYSTEM_ACTOR,
        meta=SYSTEM_META,
        outcome="failure" if denied else "success",
        target_type="scan_job",
        target_id=job.id,
        project_id=job.project_id,
        details={
            "scanner": job.scanner,
            "target": job.target,
            "error_code": job.error_code,
            "observations": len(observations) if job.status == "completed" else 0,
            "findings": job.summary.get("findings"),
        },
    )
    await session.commit()
    return job.status


def _cancel(job: ScanJob, code: str, message: str) -> None:
    now = utcnow()
    job.status = "cancelled"
    job.cancel_requested_at = now
    job.finished_at = now
    job.error_code = code
    job.error_message = message


# --------------------------------------------------------------------- API service


class ScanService:
    def __init__(
        self,
        session: AsyncSession,
        engine: ScopeEngine,
        settings: Settings,
        dispatcher: ScanDispatcher,
    ) -> None:
        self._session = session
        self._engine = engine
        self._settings = settings
        self._dispatcher = dispatcher
        self._projects = ProjectService(session)

    # ------------------------------------------------------------------ queries

    async def list(
        self, principal: Principal, project_id: uuid.UUID, params: PageParams, filters: ScanFilters
    ) -> tuple[Sequence[ScanJob], int]:
        await self._projects.get(principal, project_id)
        await self._expire()
        stmt = select(ScanJob).where(ScanJob.project_id == project_id)
        if filters.status:
            stmt = stmt.where(ScanJob.status == filters.status)
        if filters.asset_id:
            stmt = stmt.where(ScanJob.asset_id == filters.asset_id)
        if filters.scanner:
            stmt = stmt.where(ScanJob.scanner == filters.scanner)
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )
        rows = (
            (
                await self._session.execute(
                    stmt.order_by(ScanJob.created_at.desc())
                    .offset(params.offset)
                    .limit(params.page_size)
                )
            )
            .scalars()
            .all()
        )
        return rows, total

    async def get(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        job_id: uuid.UUID,
        *,
        detail: bool = False,
    ) -> ScanJob:
        await self._projects.get(principal, project_id)
        await self._expire()
        stmt = (
            select(ScanJob)
            .where(ScanJob.id == job_id, ScanJob.project_id == project_id)
            .execution_options(populate_existing=True)
        )
        if detail:
            stmt = stmt.options(selectinload(ScanJob.results), selectinload(ScanJob.evidence))
        job = (await self._session.execute(stmt)).scalar_one_or_none()
        if job is None:
            raise NotFoundError("Scan not found.")
        return job

    async def controls(self) -> ScanControls:
        return await get_controls(self._session)

    # ------------------------------------------------------------------ commands

    async def request(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        *,
        asset_id: uuid.UUID,
        scanner_name: str,
        profile: str | None,
        meta: RequestMeta,
    ) -> ScanJob:
        await self._projects.get(principal, project_id)  # non-members get 404
        await self._expire()
        # Per-project row lock: serializes quota accounting between concurrent requests.
        await self._session.execute(
            select(Project.id).where(Project.id == project_id).with_for_update()
        )

        controls = await get_controls(self._session)
        if controls.halted:
            raise ConflictError("Scanning is halted by an emergency stop.")

        asset = (
            await self._session.execute(
                select(Asset).where(Asset.id == asset_id, Asset.project_id == project_id)
            )
        ).scalar_one_or_none()
        if asset is None:
            raise NotFoundError("Asset not found.")

        cls = scanner_class(scanner_name)
        profile = profile or cls.default_profile
        if profile not in cls.profiles:
            raise InvalidRequestError(f"Unknown profile {profile!r} for the {cls.name} scanner.")
        try:
            target = cls.target_for(AssetType(asset.type), asset.value)
        except ScanError as exc:
            raise InvalidRequestError(exc.message) from exc

        technique = cls.technique_for(profile)
        eligibility = compute_eligibility(asset, self._engine, utcnow())
        allowed = {
            Technique.PASSIVE: eligibility.passive,
            Technique.ACTIVE: eligibility.active,
            Technique.INTRUSIVE: eligibility.intrusive,
        }[technique]
        if not allowed:
            reason = eligibility.reasons[0] if eligibility.reasons else "Asset is not eligible."
            record_audit(
                self._session,
                action="scan.rejected",
                actor=principal.actor,
                meta=meta,
                outcome="failure",
                target_type="asset",
                target_id=asset.id,
                project_id=project_id,
                details={
                    "scanner": cls.name.value,
                    "technique": technique.value,
                    "reason": reason,
                },
            )
            await self._session.commit()
            raise InvalidRequestError(
                f"This asset is not authorized for {technique.value} scanning: {reason}"
            )

        await self._enforce_quotas(project_id)

        job = ScanJob(
            project_id=project_id,
            asset_id=asset.id,
            scanner=cls.name.value,
            profile=profile,
            technique=technique.value,
            target=target,
            status="pending",
            requested_by_id=principal.user_id,
            correlation_id=meta.request_id,
        )
        self._session.add(job)
        await self._session.flush()
        record_audit(
            self._session,
            action="scan.requested",
            actor=principal.actor,
            meta=meta,
            target_type="scan_job",
            target_id=job.id,
            project_id=project_id,
            details={
                "asset_id": str(asset.id),
                "scanner": job.scanner,
                "profile": job.profile,
                "technique": job.technique,
                "target": job.target,
            },
        )
        await self._session.commit()

        try:
            handle = self._dispatcher.dispatch(
                str(job.id), job.scanner, self._settings.scan_timeout_for(job.scanner)
            )
        except Exception as exc:
            logger.error("scan_dispatch_failed", scan_job_id=str(job.id), error=type(exc).__name__)
            job.status = "failed"
            job.finished_at = utcnow()
            job.error_code = "dispatch_failed"
            job.error_message = "The job queue is unavailable."
            await self._session.commit()
            raise ServiceUnavailableError(
                "The scan queue is unavailable. Please try again later."
            ) from exc
        await self._session.execute(
            update(ScanJob)
            .where(ScanJob.id == job.id, ScanJob.status == "pending")
            .values(status="queued", queued_at=utcnow(), executor_task_id=handle.execute_task_id)
        )
        await self._session.commit()
        return await self.get(principal, project_id, job.id)

    async def cancel(
        self, principal: Principal, project_id: uuid.UUID, job_id: uuid.UUID, meta: RequestMeta
    ) -> ScanJob:
        await self._projects.get(principal, project_id)
        job = (
            await self._session.execute(
                select(ScanJob)
                .where(ScanJob.id == job_id, ScanJob.project_id == project_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if job is None:
            raise NotFoundError("Scan not found.")
        if job.status not in ACTIVE_STATUSES:
            raise ConflictError(f"The scan is already {job.status}.")
        previous = job.status
        _cancel(job, "cancelled", "The scan was cancelled by a user.")
        record_audit(
            self._session,
            action="scan.cancelled",
            actor=principal.actor,
            meta=meta,
            target_type="scan_job",
            target_id=job.id,
            project_id=project_id,
            details={"previous_status": previous},
        )
        await self._session.commit()
        self._revoke(job)
        return await self.get(principal, project_id, job.id)

    async def emergency_stop(self, principal: Principal, reason: str, meta: RequestMeta) -> int:
        """Halt all scanning platform-wide and cancel every active job."""
        await self._set_halted(principal, halted=True, reason=reason.strip())
        jobs = (
            (
                await self._session.execute(
                    select(ScanJob).where(ScanJob.status.in_(ACTIVE_STATUSES)).with_for_update()
                )
            )
            .scalars()
            .all()
        )
        for job in jobs:
            _cancel(job, "emergency_stop", "Cancelled by an emergency stop.")
        record_audit(
            self._session,
            action="scan.emergency_stop",
            actor=principal.actor,
            meta=meta,
            details={"reason": reason.strip(), "cancelled_jobs": len(jobs)},
        )
        await self._session.commit()
        for job in jobs:
            self._revoke(job)
        logger.warning("scan_emergency_stop", cancelled_jobs=len(jobs))
        return len(jobs)

    async def resume(self, principal: Principal, meta: RequestMeta) -> None:
        controls = await get_controls(self._session)
        if not controls.halted:
            raise ConflictError("Scanning is not halted.")
        await self._set_halted(principal, halted=False, reason=None)
        record_audit(self._session, action="scan.resumed", actor=principal.actor, meta=meta)
        await self._session.commit()

    # ------------------------------------------------------------------ internals

    async def _expire(self) -> None:
        if await expire_stale_jobs(self._session, self._settings):
            await self._session.commit()

    async def _enforce_quotas(self, project_id: uuid.UUID) -> None:
        active = int(
            (
                await self._session.execute(
                    select(func.count())
                    .select_from(ScanJob)
                    .where(ScanJob.project_id == project_id, ScanJob.status.in_(ACTIVE_STATUSES))
                )
            ).scalar_one()
        )
        if active >= self._settings.max_concurrent_scans_per_project:
            raise QuotaExceededError(
                f"This project already has {active} active scans "
                f"(limit {self._settings.max_concurrent_scans_per_project})."
            )
        daily = int(
            (
                await self._session.execute(
                    select(func.count())
                    .select_from(ScanJob)
                    .where(
                        ScanJob.project_id == project_id,
                        ScanJob.created_at >= utcnow() - timedelta(days=1),
                    )
                )
            ).scalar_one()
        )
        if daily >= self._settings.max_daily_scans_per_project:
            raise QuotaExceededError(
                f"The daily scan limit for this project "
                f"({self._settings.max_daily_scans_per_project}) has been reached."
            )

    async def _set_halted(self, principal: Principal, *, halted: bool, reason: str | None) -> None:
        setting = await self._session.get(PlatformSetting, SCANS_HALTED_KEY, with_for_update=True)
        value = {"halted": halted, "reason": reason, "by": principal.email}
        if setting is None:
            self._session.add(
                PlatformSetting(key=SCANS_HALTED_KEY, value=value, updated_by_id=principal.user_id)
            )
        else:
            setting.value = value
            setting.updated_by_id = principal.user_id
            setting.updated_at = utcnow()
        await self._session.flush()

    def _revoke(self, job: ScanJob) -> None:
        if not job.executor_task_id:
            return
        try:
            self._dispatcher.revoke(job.executor_task_id)
        except Exception as exc:  # noqa: BLE001 - the DB state is authoritative
            logger.warning("scan_revoke_failed", scan_job_id=str(job.id), error=type(exc).__name__)
