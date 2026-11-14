"""Risk scoring service: weights, (re)scoring with history, posture and trend.

Scores are recomputed whenever an input changes:

* a scan or correlation creates or updates findings (``scan`` / ``correlation``);
* an asset's criticality or exposure changes (``asset_updated``);
* CVE data changes — NVD refresh, KEV or EPSS (``intel_updated``);
* an administrator changes the weights (``weights_changed``);
* daily, because the exposure-window factor grows with time (``daily``).

A ``finding_risk_changes`` row is written only when the score, band or model
version actually changes, so the history shows real movements.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import Principal, RequestMeta
from app.core.errors import InvalidRequestError
from app.models import (
    Asset,
    Cve,
    Finding,
    FindingRiskChange,
    PlatformSetting,
    Project,
    ProjectRiskSnapshot,
)
from app.services.audit import record_audit
from app.services.events import EventType, emit
from sentinelx_security.risk import (
    MODEL_VERSION,
    RiskInputs,
    RiskWeights,
    WeightsError,
    posture,
    score,
)

RISK_WEIGHTS_KEY: Final = "risk.weights"
ACTIVE: Final = ("open", "acknowledged")
TREND_DAYS: Final = 30


def utcnow() -> datetime:
    return datetime.now(UTC)


async def load_weights(session: AsyncSession) -> RiskWeights:
    setting = await session.get(PlatformSetting, RISK_WEIGHTS_KEY)
    if setting is None:
        return RiskWeights()
    try:
        return RiskWeights.from_mapping(setting.value)
    except WeightsError:
        return RiskWeights()  # never fail scoring on a corrupted setting


async def rescore(
    session: AsyncSession,
    *,
    trigger: str,
    finding_ids: Iterable[uuid.UUID] | None = None,
    project_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    cve_ids: Iterable[str] | None = None,
    weights: RiskWeights | None = None,
) -> int:
    """Recompute risk for the selected findings. Returns how many changed."""
    stmt = (
        select(Finding, Asset, Cve)
        .join(Asset, Asset.id == Finding.asset_id)
        .outerjoin(Cve, Cve.id == Finding.cve_id)
    )
    if finding_ids is not None:
        ids = list(finding_ids)
        if not ids:
            return 0
        stmt = stmt.where(Finding.id.in_(ids))
    if project_id is not None:
        stmt = stmt.where(Finding.project_id == project_id)
    if asset_id is not None:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if cve_ids is not None:
        cves = list(cve_ids)
        if not cves:
            return 0
        stmt = stmt.where(Finding.cve_id.in_(cves))

    await session.flush()  # sessions do not autoflush; score the pending state
    weights = weights or await load_weights(session)
    now = utcnow()
    changed = 0
    for finding, asset, cve in (await session.execute(stmt)).all():
        result = score(
            RiskInputs(
                severity=finding.severity,
                confidence=finding.confidence,
                cvss_score=cve.cvss_score if cve is not None else None,
                kev=bool(cve is not None and cve.kev_added_on),
                epss=cve.epss_score if cve is not None else None,
                asset_criticality=asset.criticality,
                asset_exposure=asset.exposure,
                first_seen_at=finding.first_seen_at,
            ),
            weights,
            now,
        )
        factors = result.factors_dict()
        previous_band = finding.risk_band
        if (
            finding.risk_score != result.score
            or finding.risk_band != result.band
            or finding.risk_model_version != result.model_version
        ):
            session.add(
                FindingRiskChange(
                    finding_id=finding.id,
                    score=result.score,
                    band=result.band,
                    model_version=result.model_version,
                    trigger=trigger[:64],
                    factors=factors,
                    calculated_at=now,
                )
            )
            changed += 1
        finding.risk_score = result.score
        finding.risk_band = result.band
        finding.risk_model_version = result.model_version
        finding.risk_factors = factors
        finding.risk_explanation = result.explanation
        finding.risk_calculated_at = now
        if previous_band is not None and previous_band != result.band:
            await emit(
                session,
                project_id=finding.project_id,
                event_type=EventType.FINDING_RISK_CHANGED,
                severity=result.band,
                title=f"{finding.title}: risk {previous_band} → {result.band}",
                asset_id=finding.asset_id,
                finding_id=finding.id,
                details={
                    "from": previous_band,
                    "to": result.band,
                    "score": result.score,
                    "trigger": trigger,
                },
                dedup_key=f"finding.risk_band_changed:{finding.id}:{result.band}",
            )
    await session.flush()
    return changed


async def project_posture(session: AsyncSession, project_id: uuid.UUID) -> dict[str, Any]:
    scores = (
        (
            await session.execute(
                select(Finding.risk_score).where(
                    Finding.project_id == project_id,
                    Finding.status.in_(ACTIVE),
                    Finding.risk_score.is_not(None),
                )
            )
        )
        .scalars()
        .all()
    )
    return posture(float(s) for s in scores if s is not None)


async def snapshot(session: AsyncSession, project_id: uuid.UUID, day: date | None = None) -> None:
    day = day or utcnow().date()
    await session.flush()  # sessions do not autoflush; include pending status changes
    current = await project_posture(session, project_id)
    row = (
        await session.execute(
            select(ProjectRiskSnapshot).where(
                ProjectRiskSnapshot.project_id == project_id, ProjectRiskSnapshot.day == day
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = ProjectRiskSnapshot(project_id=project_id, day=day)
        session.add(row)
    row.score = current["score"]
    row.band = current["band"]
    row.active = current["active"]
    row.counts = current["counts"]
    row.model_version = MODEL_VERSION
    row.calculated_at = utcnow()
    await session.flush()


async def snapshot_all(session: AsyncSession) -> int:
    projects = (await session.execute(select(Project.id))).scalars().all()
    for project_id in projects:
        await snapshot(session, project_id)
    return len(projects)


async def trend(session: AsyncSession, project_id: uuid.UUID) -> Sequence[ProjectRiskSnapshot]:
    since = utcnow().date() - timedelta(days=TREND_DAYS)
    return (
        (
            await session.execute(
                select(ProjectRiskSnapshot)
                .where(
                    ProjectRiskSnapshot.project_id == project_id, ProjectRiskSnapshot.day >= since
                )
                .order_by(ProjectRiskSnapshot.day)
            )
        )
        .scalars()
        .all()
    )


async def top_risks(
    session: AsyncSession, project_id: uuid.UUID, limit: int = 10
) -> Sequence[Finding]:
    return (
        (
            await session.execute(
                select(Finding)
                .where(
                    Finding.project_id == project_id,
                    Finding.status.in_(ACTIVE),
                    Finding.risk_score.is_not(None),
                )
                .order_by(Finding.risk_score.desc(), Finding.last_seen_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )


async def save_weights(
    session: AsyncSession,
    principal: Principal,
    values: dict[str, Any] | None,
    meta: RequestMeta,
) -> tuple[RiskWeights, int]:
    """Validate and store weights (``None`` resets to defaults), then rescore everything."""
    try:
        weights = RiskWeights.from_mapping(values) if values is not None else RiskWeights()
    except WeightsError as exc:
        raise InvalidRequestError(str(exc)) from exc
    previous = await load_weights(session)
    setting = await session.get(PlatformSetting, RISK_WEIGHTS_KEY, with_for_update=True)
    if setting is None:
        setting = PlatformSetting(key=RISK_WEIGHTS_KEY, value=weights.to_dict())
        session.add(setting)
    setting.value = weights.to_dict()
    setting.updated_by_id = principal.user_id
    setting.updated_at = utcnow()
    changes = {
        k: {"from": v, "to": weights.to_dict()[k]}
        for k, v in previous.to_dict().items()
        if weights.to_dict()[k] != v
    }
    record_audit(
        session,
        action="risk.weights_reset" if values is None else "risk.weights_updated",
        actor=principal.actor,
        meta=meta,
        details={"changes": changes, "model_version": MODEL_VERSION},
    )
    changed = await rescore(session, trigger="weights_changed", weights=weights)
    await snapshot_all(session)
    await session.commit()
    return weights, changed
