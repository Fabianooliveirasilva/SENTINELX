"""Cross-project read models, scoped to the projects the caller can access."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import Principal
from app.core.errors import NotFoundError
from app.models import Asset, Finding, Project, ScanJob
from app.models.asset import ASSET_TYPES
from app.repositories.projects import scope_to_principal
from app.schemas.pagination import PageParams

ACTIVE: Final = ("open", "acknowledged")
RECENT: Final = 10


async def _accessible(
    session: AsyncSession, principal: Principal, project_id: uuid.UUID | None
) -> dict[uuid.UUID, str]:
    stmt = scope_to_principal(select(Project), principal)
    if project_id is not None:
        stmt = stmt.where(Project.id == project_id)
    rows = (await session.execute(stmt)).scalars().all()
    if project_id is not None and not rows:
        raise NotFoundError("Project not found.")
    return {p.id: p.name for p in rows}


def _like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


async def list_findings(
    session: AsyncSession,
    principal: Principal,
    params: PageParams,
    *,
    project_id: uuid.UUID | None,
    severity: str | None,
    status: str | None,
    active_only: bool,
    search: str | None,
) -> dict[str, Any]:
    names = await _accessible(session, principal, project_id)
    ids = list(names)
    conditions: list[Any] = [Finding.project_id.in_(ids) if ids else Finding.project_id.is_(None)]
    if severity:
        conditions.append(Finding.severity == severity)
    if status:
        conditions.append(Finding.status == status)
    elif active_only:
        conditions.append(Finding.status.in_(ACTIVE))
    if search:
        conditions.append(Finding.title.ilike(_like(search), escape="\\"))
    total = int(
        (
            await session.execute(select(func.count()).select_from(Finding).where(*conditions))
        ).scalar_one()
    )
    by_severity = {
        sev: int(n)
        for sev, n in await session.execute(
            select(Finding.severity, func.count()).where(*conditions).group_by(Finding.severity)
        )
    }
    rows = (
        await session.execute(
            select(Finding, Asset.value)
            .join(Asset, Asset.id == Finding.asset_id)
            .where(*conditions)
            .order_by(
                Finding.risk_score.desc().nulls_last(), Finding.first_seen_at.desc(), Finding.id
            )
            .offset(params.offset)
            .limit(params.page_size)
        )
    ).all()
    return {
        "items": [
            {
                "id": str(f.id),
                "project_id": str(f.project_id),
                "project_name": names.get(f.project_id, ""),
                "asset": asset,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "source": f.source,
                "risk_band": f.risk_band,
                "risk_score": f.risk_score,
                "cve_id": f.cve_id,
                "first_seen_at": f.first_seen_at,
                "last_seen_at": f.last_seen_at,
            }
            for f, asset in rows
        ],
        "total": total,
        "page": params.page,
        "page_size": params.page_size,
        "by_severity": by_severity,
    }


async def reconnaissance(
    session: AsyncSession, principal: Principal, project_id: uuid.UUID | None
) -> dict[str, Any]:
    names = await _accessible(session, principal, project_id)
    ids = list(names)
    now = datetime.now(UTC)

    def in_scope(column: Any) -> Any:
        return column.in_(ids) if ids else column.is_(None)

    active_assets = (in_scope(Asset.project_id), Asset.status == "active")
    by_type = dict.fromkeys(ASSET_TYPES, 0)
    for kind, n in await session.execute(
        select(Asset.type, func.count()).where(*active_assets).group_by(Asset.type)
    ):
        by_type[kind] = int(n)
    by_exposure = dict.fromkeys(("external", "internal", "unknown"), 0)
    for exposure, n in await session.execute(
        select(Asset.exposure, func.count()).where(*active_assets).group_by(Asset.exposure)
    ):
        by_exposure[exposure] = int(n)
    new_7d = int(
        (
            await session.execute(
                select(func.count())
                .select_from(Asset)
                .where(*active_assets, Asset.created_at >= now - timedelta(days=7))
            )
        ).scalar_one()
    )
    since = now - timedelta(days=30)
    scans = (in_scope(ScanJob.project_id), ScanJob.created_at >= since)
    by_scanner = {
        k: int(n)
        for k, n in await session.execute(
            select(ScanJob.scanner, func.count()).where(*scans).group_by(ScanJob.scanner)
        )
    }
    by_status = {
        k: int(n)
        for k, n in await session.execute(
            select(ScanJob.status, func.count()).where(*scans).group_by(ScanJob.status)
        )
    }
    recent_assets = (
        (
            await session.execute(
                select(Asset)
                .where(*active_assets)
                .order_by(Asset.created_at.desc(), Asset.id)
                .limit(RECENT)
            )
        )
        .scalars()
        .all()
    )
    recent_scans = (
        (
            await session.execute(
                select(ScanJob)
                .where(in_scope(ScanJob.project_id))
                .order_by(ScanJob.created_at.desc(), ScanJob.id)
                .limit(RECENT)
            )
        )
        .scalars()
        .all()
    )
    return {
        "generated_at": now,
        "projects": len(ids),
        "assets_total": sum(by_type.values()),
        "assets_new_7d": new_7d,
        "assets_by_type": by_type,
        "assets_by_exposure": by_exposure,
        "scans_30d_by_scanner": by_scanner,
        "scans_30d_by_status": by_status,
        "recent_assets": [
            {
                "id": str(a.id),
                "project_id": str(a.project_id),
                "project_name": names.get(a.project_id, ""),
                "type": a.type,
                "value": a.value,
                "exposure": a.exposure,
                "created_at": a.created_at,
            }
            for a in recent_assets
        ],
        "recent_scans": [
            {
                "id": str(s.id),
                "project_id": str(s.project_id),
                "project_name": names.get(s.project_id, ""),
                "scanner": s.scanner,
                "profile": s.profile,
                "target": s.target,
                "status": s.status,
                "created_at": s.created_at,
                "finished_at": s.finished_at,
            }
            for s in recent_scans
        ],
        "empty": not ids,
    }
