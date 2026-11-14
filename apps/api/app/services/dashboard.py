"""Dashboard: platform or project overview computed from stored data only.

Every number is aggregated from the projects the caller can access (all projects
for administrators, memberships otherwise). Nothing is cached or estimated.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any, Final

from sqlalchemy import Date, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import Principal
from app.core.errors import NotFoundError
from app.models import (
    Asset,
    Cve,
    Finding,
    FindingStatusChange,
    Project,
    ProjectRiskSnapshot,
    ScanJob,
)
from app.models.finding import SEVERITIES
from app.models.scan import ACTIVE_STATUSES
from app.repositories.projects import scope_to_principal
from app.services.risk import project_posture

ACTIVE_FINDINGS: Final = ("open", "acknowledged")
TREND_DAYS: Final = 30
ACTIVITY_DAYS: Final = 14
REMEDIATION_WEEKS: Final = 8
RECENT_FINDINGS: Final = 8
EXPOSURES: Final = ("external", "internal", "unknown")


def utcnow() -> datetime:
    return datetime.now(UTC)


async def _project_ids(
    session: AsyncSession, principal: Principal, project_id: uuid.UUID | None
) -> list[tuple[uuid.UUID, str]]:
    stmt = scope_to_principal(select(Project), principal)
    if project_id is not None:
        stmt = stmt.where(Project.id == project_id)
    rows = (await session.execute(stmt.order_by(Project.name))).scalars().all()
    if project_id is not None and not rows:
        raise NotFoundError("Project not found.")
    return [(p.id, p.name) for p in rows]


def _utc(column: Any) -> Any:
    """Day and week boundaries in UTC, whatever the database session time zone."""
    return func.timezone("UTC", column)


def _days(count: int, today: date) -> list[date]:
    return [today - timedelta(days=offset) for offset in range(count - 1, -1, -1)]


async def build_dashboard(
    session: AsyncSession, principal: Principal, project_id: uuid.UUID | None
) -> dict[str, Any]:
    projects = await _project_ids(session, principal, project_id)
    ids: Sequence[uuid.UUID] = [pid for pid, _ in projects]
    names = dict(projects)
    now = utcnow()
    today = now.date()
    empty = not ids

    def scoped(column: Any) -> Any:
        return column.in_(ids) if ids else column.is_(None)

    # ---------------------------------------------------------------- totals
    assets_by_exposure = dict.fromkeys(EXPOSURES, 0)
    for exposure, count in await session.execute(
        select(Asset.exposure, func.count())
        .where(scoped(Asset.project_id), Asset.status == "active")
        .group_by(Asset.exposure)
    ):
        assets_by_exposure[exposure] = int(count)
    active_scans = int(
        (
            await session.execute(
                select(func.count())
                .select_from(ScanJob)
                .where(scoped(ScanJob.project_id), ScanJob.status.in_(ACTIVE_STATUSES))
            )
        ).scalar_one()
    )
    distribution = dict.fromkeys(reversed(SEVERITIES), 0)
    for band, count in await session.execute(
        select(Finding.risk_band, func.count())
        .where(scoped(Finding.project_id), Finding.status.in_(ACTIVE_FINDINGS))
        .group_by(Finding.risk_band)
    ):
        distribution[band or "info"] += int(count)
    kev = int(
        (
            await session.execute(
                select(func.count())
                .select_from(Finding)
                .join(Cve, Cve.id == Finding.cve_id)
                .where(
                    scoped(Finding.project_id),
                    Finding.status.in_(ACTIVE_FINDINGS),
                    Cve.kev_added_on.is_not(None),
                )
            )
        ).scalar_one()
    )

    # ---------------------------------------------------------------- posture
    postures = []
    for pid in ids:
        value = await project_posture(session, pid)
        postures.append({"id": str(pid), "name": names[pid], **value})
    postures.sort(key=lambda p: (-p["score"], p["name"]))
    worst = postures[0] if postures else None
    since = today - timedelta(days=TREND_DAYS - 1)
    trend_rows = dict(
        (
            await session.execute(
                select(ProjectRiskSnapshot.day, func.max(ProjectRiskSnapshot.score))
                .where(scoped(ProjectRiskSnapshot.project_id), ProjectRiskSnapshot.day >= since)
                .group_by(ProjectRiskSnapshot.day)
            )
        ).all()
    )
    trend = [
        {"day": day.isoformat(), "score": round(float(trend_rows[day]), 1)}
        for day in _days(TREND_DAYS, today)
        if day in trend_rows
    ]

    # ---------------------------------------------------------------- scan activity
    activity_since = datetime.combine(
        today - timedelta(days=ACTIVITY_DAYS - 1), datetime.min.time(), tzinfo=UTC
    )
    day_column = cast(_utc(ScanJob.created_at), Date)
    counts: dict[tuple[date, str], int] = {
        (day, status): int(n)
        for day, status, n in await session.execute(
            select(day_column, ScanJob.status, func.count())
            .where(scoped(ScanJob.project_id), ScanJob.created_at >= activity_since)
            .group_by(day_column, ScanJob.status)
        )
    }
    activity = [
        {
            "day": day.isoformat(),
            "completed": counts.get((day, "completed"), 0),
            "failed": counts.get((day, "failed"), 0),
            "cancelled": counts.get((day, "cancelled"), 0),
            "active": sum(counts.get((day, s), 0) for s in ACTIVE_STATUSES),
        }
        for day in _days(ACTIVITY_DAYS, today)
    ]

    # ---------------------------------------------------------------- remediation
    week_start = today - timedelta(days=today.weekday())
    weeks = [week_start - timedelta(weeks=w) for w in range(REMEDIATION_WEEKS - 1, -1, -1)]
    first_week = datetime.combine(weeks[0], datetime.min.time(), tzinfo=UTC)
    opened_week = cast(func.date_trunc("week", _utc(Finding.first_seen_at)), Date)
    opened = {
        week: int(n)
        for week, n in await session.execute(
            select(opened_week, func.count())
            .where(scoped(Finding.project_id), Finding.first_seen_at >= first_week)
            .group_by(opened_week)
        )
    }
    resolved_week = cast(func.date_trunc("week", _utc(FindingStatusChange.created_at)), Date)
    resolved = {
        week: int(n)
        for week, n in await session.execute(
            select(resolved_week, func.count())
            .join(Finding, Finding.id == FindingStatusChange.finding_id)
            .where(
                scoped(Finding.project_id),
                FindingStatusChange.to_status == "resolved",
                FindingStatusChange.created_at >= first_week,
            )
            .group_by(resolved_week)
        )
    }
    weekly = [
        {"week": w.isoformat(), "opened": opened.get(w, 0), "resolved": resolved.get(w, 0)}
        for w in weeks
    ]
    by_status = dict.fromkeys(
        ("open", "acknowledged", "resolved", "false_positive", "accepted_risk"), 0
    )
    for status, n in await session.execute(
        select(Finding.status, func.count())
        .where(scoped(Finding.project_id))
        .group_by(Finding.status)
    ):
        by_status[status] = int(n)
    total = sum(by_status.values())
    closed = by_status["resolved"] + by_status["false_positive"] + by_status["accepted_risk"]

    # ---------------------------------------------------------------- recent findings
    recent = (
        await session.execute(
            select(Finding, Asset.value)
            .join(Asset, Asset.id == Finding.asset_id)
            .where(scoped(Finding.project_id), Finding.status.in_(ACTIVE_FINDINGS))
            .order_by(Finding.first_seen_at.desc())
            .limit(RECENT_FINDINGS)
        )
    ).all()

    return {
        "generated_at": now.isoformat(),
        "scope": {
            "project_id": str(project_id) if project_id else None,
            "projects": len(ids),
        },
        "totals": {
            "assets": sum(assets_by_exposure.values()),
            "active_scans": active_scans,
            "active_findings": sum(distribution.values()),
            "critical_findings": distribution["critical"],
            "high_findings": distribution["high"],
            "known_exploited_findings": kev,
        },
        "posture": {
            "score": worst["score"] if worst else 0.0,
            "band": worst["band"] if worst else "info",
            "worst_project": {"id": worst["id"], "name": worst["name"]} if worst else None,
        },
        "posture_trend": trend,
        "risk_distribution": distribution,
        "assets_by_exposure": assets_by_exposure,
        "scan_activity": activity,
        "remediation": {
            "weekly": weekly,
            "by_status": by_status,
            "closed_ratio": round(closed / total, 3) if total else None,
        },
        "recent_findings": [
            {
                "id": str(f.id),
                "project_id": str(f.project_id),
                "project_name": names.get(f.project_id, ""),
                "title": f.title,
                "severity": f.severity,
                "risk_band": f.risk_band,
                "risk_score": f.risk_score,
                "asset": asset,
                "first_seen_at": f.first_seen_at.isoformat(),
            }
            for f, asset in recent
        ],
        "projects": [
            {
                "id": p["id"],
                "name": p["name"],
                "score": p["score"],
                "band": p["band"],
                "active": p["active"],
            }
            for p in postures[:6]
        ],
        "empty": empty,
    }
