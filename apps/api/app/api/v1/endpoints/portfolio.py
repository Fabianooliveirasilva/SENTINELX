"""Cross-project views: vulnerabilities and reconnaissance overview."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.core.context import Principal
from app.core.permissions import Permission
from app.dependencies.auth import require_permission
from app.dependencies.core import SessionDep
from app.schemas.common import error_responses
from app.schemas.findings import FindingStatus, Severity
from app.schemas.pagination import PageParams, page_params
from app.schemas.portfolio import PortfolioFindingsPage, ReconOverview
from app.services import portfolio

router = APIRouter(tags=["portfolio"])

CanReadFindings = Annotated[Principal, Depends(require_permission(Permission.FINDINGS_READ))]
CanReadAssets = Annotated[Principal, Depends(require_permission(Permission.ASSETS_READ))]


@router.get(
    "/vulnerabilities",
    responses=error_responses(401, 403, 404, 422),
    summary="Findings across the projects the caller can access (highest risk first)",
)
async def vulnerabilities(
    principal: CanReadFindings,
    session: SessionDep,
    params: Annotated[PageParams, Depends(page_params)],
    project_id: uuid.UUID | None = None,
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    active: Annotated[bool, Query(description="Only open or acknowledged findings")] = True,
    search: Annotated[str | None, Query(max_length=200)] = None,
) -> PortfolioFindingsPage:
    data = await portfolio.list_findings(
        session,
        principal,
        params,
        project_id=project_id,
        severity=severity,
        status=status,
        active_only=active,
        search=search,
    )
    return PortfolioFindingsPage.model_validate(data)


@router.get(
    "/reconnaissance",
    responses=error_responses(401, 403, 404, 422),
    summary="Asset discovery and reconnaissance activity across accessible projects",
)
async def reconnaissance(
    principal: CanReadAssets, session: SessionDep, project_id: uuid.UUID | None = None
) -> ReconOverview:
    return ReconOverview.model_validate(
        await portfolio.reconnaissance(session, principal, project_id)
    )
