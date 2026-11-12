"""Findings: ingestion from completed scans and analyst triage.

Ingestion (worker side, inside the transaction that records a scan):

* Observations are mapped to finding candidates by the deterministic rules in
  ``sentinelx_security.findings``; identity is ``sha256(asset, rule, location)``.
* A new fingerprint creates an ``open`` finding; a known one is updated
  (last seen, occurrence count). A ``resolved`` finding that is observed again is
  **reopened** (regression). ``false_positive`` / ``accepted_risk`` decisions made by
  an analyst are respected and never reopened automatically.
* Open or acknowledged findings from the same scanner *and profile* on the same
  asset that are not observed by a completed scan are marked ``resolved``.

Every automatic or manual status change is recorded in ``finding_status_changes``.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import Principal, RequestMeta
from app.core.errors import ConflictError, InvalidRequestError, NotFoundError
from app.models import (
    Finding,
    FindingOccurrence,
    FindingRiskChange,
    FindingStatusChange,
    ScanJob,
)
from app.models.finding import FINDING_STATUSES, SEVERITIES
from app.repositories.sql import LIKE_ESCAPE, contains_pattern
from app.schemas.pagination import PageParams
from app.services.audit import record_audit
from app.services.events import CERTIFICATE_RULES, EventType, emit
from app.services.projects import ProjectService
from app.services.risk import rescore, snapshot
from sentinelx_security.findings import RULESET_VERSION, FindingCandidate, derive_findings

ACTIVE_FINDING_STATUSES: Final = ("open", "acknowledged")
REASON_REQUIRED: Final = frozenset({"false_positive", "accepted_risk", "resolved"})
MAX_OCCURRENCES_SHOWN: Final = 20


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class IngestResult:
    new: int = 0
    updated: int = 0
    reopened: int = 0
    resolved: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "new": self.new,
            "updated": self.updated,
            "reopened": self.reopened,
            "resolved": self.resolved,
        }


@dataclass(frozen=True, slots=True)
class FindingFilters:
    status: str | None = None
    severity: str | None = None
    asset_id: uuid.UUID | None = None
    source: str | None = None
    search: str | None = None
    active_only: bool = False
    risk_band: str | None = None
    sort: str = "risk"


def _by(scope: IngestScope) -> str:
    return f"scan {scope.scan_job_id}" if scope.scan_job_id else "intelligence re-correlation"


def _history(
    finding: Finding,
    to_status: str,
    reason: str,
    *,
    from_status: str | None,
    by_id: uuid.UUID | None = None,
    by_email: str | None = None,
) -> FindingStatusChange:
    return FindingStatusChange(
        finding_id=finding.id,
        from_status=from_status,
        to_status=to_status,
        reason=reason[:2000],
        changed_by_id=by_id,
        changed_by_email=by_email,
    )


async def _finding_event(
    session: AsyncSession,
    finding: Finding,
    event_type: EventType,
    scope: IngestScope,
    *,
    severity: str | None = None,
) -> None:
    await emit(
        session,
        project_id=finding.project_id,
        event_type=event_type,
        severity=severity or finding.severity,
        title=finding.title,
        asset_id=finding.asset_id,
        finding_id=finding.id,
        scan_job_id=scope.scan_job_id,
        details={
            "rule_id": finding.rule_id,
            "location": finding.location,
            "source": scope.source,
            "profile": scope.profile,
        },
    )


@dataclass(frozen=True, slots=True)
class IngestScope:
    """Where candidates come from; auto-resolution is limited to the same scope."""

    project_id: uuid.UUID
    asset_id: uuid.UUID
    source: str
    profile: str
    scan_job_id: uuid.UUID | None

    @classmethod
    def for_job(cls, job: ScanJob) -> IngestScope:
        return cls(job.project_id, job.asset_id, job.scanner, job.profile, job.id)


async def ingest_findings(
    session: AsyncSession, job: ScanJob, observations: Sequence[dict[str, Any]]
) -> IngestResult:
    """Create, update, reopen and auto-resolve findings for a completed scan."""
    return await ingest_candidates(session, IngestScope.for_job(job), derive_findings(observations))


async def ingest_candidates(
    session: AsyncSession, scope: IngestScope, candidates: Sequence[FindingCandidate]
) -> IngestResult:
    now = utcnow()
    asset_key = str(scope.asset_id)
    seen: set[str] = set()
    touched: list[uuid.UUID] = []
    new = updated = reopened = 0

    for candidate in candidates:
        fingerprint = candidate.fingerprint(asset_key)
        seen.add(fingerprint)
        finding = (
            await session.execute(
                select(Finding)
                .where(Finding.project_id == scope.project_id, Finding.fingerprint == fingerprint)
                .with_for_update()
            )
        ).scalar_one_or_none()
        fields = {
            "rule_id": candidate.rule_id[:200],
            "ruleset_version": RULESET_VERSION,
            "category": candidate.category[:32],
            "title": candidate.title[:300],
            "description": candidate.description,
            "remediation": candidate.remediation,
            "location": candidate.key[:512],
            "severity": candidate.severity.value,
            "confidence": candidate.confidence.value,
            "cwe": candidate.cwe,
            "references": [r[:500] for r in candidate.references],
            "cve_id": candidate.rule_id[4:36] if candidate.rule_id.startswith("cve.") else None,
        }
        if finding is None:
            finding = Finding(
                project_id=scope.project_id,
                asset_id=scope.asset_id,
                fingerprint=fingerprint,
                source=scope.source,
                status="open",
                first_seen_at=now,
                last_seen_at=now,
                last_scan_job_id=scope.scan_job_id,
                last_profile=scope.profile,
                occurrence_count=1,
                **fields,
            )
            session.add(finding)
            await session.flush()
            session.add(
                _history(finding, "open", f"First observed by {_by(scope)}.", from_status=None)
            )
            await _finding_event(session, finding, EventType.FINDING_CREATED, scope)
            if finding.rule_id in CERTIFICATE_RULES:
                await _finding_event(session, finding, EventType.CERTIFICATE_EXPIRING, scope)
            new += 1
        else:
            for name, value in fields.items():
                setattr(finding, name, value)
            finding.last_seen_at = now
            finding.last_scan_job_id = scope.scan_job_id
            finding.last_profile = scope.profile
            finding.occurrence_count += 1
            if finding.status == "resolved":
                session.add(
                    _history(
                        finding,
                        "open",
                        f"Observed again by {_by(scope)} (regression).",
                        from_status="resolved",
                    )
                )
                finding.status = "open"
                finding.status_reason = "Regression: observed again after being resolved."
                finding.resolved_at = None
                await _finding_event(session, finding, EventType.FINDING_REOPENED, scope)
                reopened += 1
            else:
                updated += 1
        touched.append(finding.id)
        session.add(
            FindingOccurrence(
                finding_id=finding.id,
                scan_job_id=scope.scan_job_id,
                observation=dict(candidate.observation),
            )
        )

    stale = (
        (
            await session.execute(
                select(Finding)
                .where(
                    Finding.project_id == scope.project_id,
                    Finding.asset_id == scope.asset_id,
                    Finding.source == scope.source,
                    Finding.last_profile == scope.profile,
                    Finding.status.in_(ACTIVE_FINDING_STATUSES),
                    Finding.fingerprint.not_in(seen) if seen else Finding.fingerprint.is_not(None),
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for finding in stale:
        session.add(
            _history(
                finding,
                "resolved",
                f"Not observed by {_by(scope)} ({scope.source}/{scope.profile}).",
                from_status=finding.status,
            )
        )
        finding.status = "resolved"
        finding.status_reason = "No longer observed."
        finding.resolved_at = now
        await _finding_event(session, finding, EventType.FINDING_RESOLVED, scope, severity="info")
    await rescore(
        session,
        trigger="scan" if scope.scan_job_id else "correlation",
        finding_ids=touched,
    )
    return IngestResult(new=new, updated=updated, reopened=reopened, resolved=len(stale))


class FindingService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._projects = ProjectService(session)

    async def list(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        params: PageParams,
        filters: FindingFilters,
    ) -> tuple[Sequence[Finding], int]:
        await self._projects.get(principal, project_id)
        stmt = select(Finding).where(Finding.project_id == project_id)
        if filters.status:
            stmt = stmt.where(Finding.status == filters.status)
        elif filters.active_only:
            stmt = stmt.where(Finding.status.in_(ACTIVE_FINDING_STATUSES))
        if filters.severity:
            stmt = stmt.where(Finding.severity == filters.severity)
        if filters.risk_band:
            stmt = stmt.where(Finding.risk_band == filters.risk_band)
        if filters.asset_id:
            stmt = stmt.where(Finding.asset_id == filters.asset_id)
        if filters.source:
            stmt = stmt.where(Finding.source == filters.source)
        if filters.search:
            pattern = contains_pattern(filters.search)
            stmt = stmt.where(
                or_(
                    Finding.title.ilike(pattern, escape=LIKE_ESCAPE),
                    Finding.location.ilike(pattern, escape=LIKE_ESCAPE),
                )
            )
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )
        severity_order = func.array_position(list(SEVERITIES), Finding.severity)
        order = {
            "risk": (Finding.risk_score.desc().nulls_last(), severity_order.desc()),
            "severity": (severity_order.desc(), Finding.risk_score.desc().nulls_last()),
            "last_seen": (Finding.last_seen_at.desc(),),
        }.get(filters.sort, (Finding.risk_score.desc().nulls_last(),))
        rows = (
            (
                await self._session.execute(
                    stmt.order_by(*order, Finding.last_seen_at.desc())
                    .offset(params.offset)
                    .limit(params.page_size)
                )
            )
            .scalars()
            .all()
        )
        return rows, total

    async def summary(self, principal: Principal, project_id: uuid.UUID) -> dict[str, Any]:
        await self._projects.get(principal, project_id)
        rows = (
            await self._session.execute(
                select(Finding.status, Finding.severity, func.count())
                .where(Finding.project_id == project_id)
                .group_by(Finding.status, Finding.severity)
            )
        ).all()
        by_status = dict.fromkeys(FINDING_STATUSES, 0)
        active_by_severity = dict.fromkeys(SEVERITIES, 0)
        for status, severity, count in rows:
            by_status[status] += count
            if status in ACTIVE_FINDING_STATUSES:
                active_by_severity[severity] += count
        return {"by_status": by_status, "active_by_severity": active_by_severity}

    async def get(
        self, principal: Principal, project_id: uuid.UUID, finding_id: uuid.UUID
    ) -> tuple[Finding, Sequence[FindingOccurrence], Sequence[FindingStatusChange]]:
        await self._projects.get(principal, project_id)
        finding = (
            await self._session.execute(
                select(Finding)
                .where(Finding.id == finding_id, Finding.project_id == project_id)
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if finding is None:
            raise NotFoundError("Finding not found.")
        occurrences = (
            (
                await self._session.execute(
                    select(FindingOccurrence)
                    .where(FindingOccurrence.finding_id == finding.id)
                    .order_by(FindingOccurrence.observed_at.desc())
                    .limit(MAX_OCCURRENCES_SHOWN)
                )
            )
            .scalars()
            .all()
        )
        history = (
            (
                await self._session.execute(
                    select(FindingStatusChange)
                    .where(FindingStatusChange.finding_id == finding.id)
                    .order_by(FindingStatusChange.created_at.desc())
                )
            )
            .scalars()
            .all()
        )
        return finding, occurrences, history

    async def risk_history(self, finding_id: uuid.UUID) -> Sequence[FindingRiskChange]:
        """Caller must have loaded the finding through :meth:`get` (tenancy check)."""
        return (
            (
                await self._session.execute(
                    select(FindingRiskChange)
                    .where(FindingRiskChange.finding_id == finding_id)
                    .order_by(FindingRiskChange.calculated_at.desc())
                    .limit(20)
                )
            )
            .scalars()
            .all()
        )

    async def change_status(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        finding_id: uuid.UUID,
        *,
        status: str,
        reason: str,
        meta: RequestMeta,
    ) -> Finding:
        await self._projects.get(principal, project_id)
        finding = (
            await self._session.execute(
                select(Finding)
                .where(Finding.id == finding_id, Finding.project_id == project_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if finding is None:
            raise NotFoundError("Finding not found.")
        if status not in FINDING_STATUSES:
            raise InvalidRequestError(f"Unknown status {status!r}.")
        if status == finding.status:
            raise ConflictError(f"The finding is already {status}.")
        reason = reason.strip()
        if status in REASON_REQUIRED and len(reason) < 3:
            raise InvalidRequestError("A reason is required for this status.")
        previous = finding.status
        self._session.add(
            _history(
                finding,
                status,
                reason,
                from_status=previous,
                by_id=principal.user_id,
                by_email=principal.email,
            )
        )
        finding.status = status
        finding.status_reason = reason or None
        finding.resolved_at = utcnow() if status == "resolved" else None
        await snapshot(self._session, project_id)
        record_audit(
            self._session,
            action="finding.status_changed",
            actor=principal.actor,
            meta=meta,
            target_type="finding",
            target_id=finding.id,
            project_id=project_id,
            details={"from": previous, "to": status, "reason": reason, "rule_id": finding.rule_id},
        )
        await emit(
            self._session,
            project_id=project_id,
            event_type=EventType.FINDING_STATUS_CHANGED,
            severity="info",
            title=f"{finding.title}: {previous} → {status}",
            asset_id=finding.asset_id,
            finding_id=finding.id,
            details={"from": previous, "to": status, "reason": reason, "rule_id": finding.rule_id},
            actor_email=principal.email,
            dedup_key=f"finding.status_changed:{finding.id}:{status}",
        )
        await self._session.commit()
        await self._session.refresh(finding)
        return finding
