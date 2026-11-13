"""AI security analyst: request, read and review advisory analyses."""

from __future__ import annotations

import uuid
from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.core.context import Principal
from app.core.permissions import Permission
from app.dependencies.auth import require_permission
from app.dependencies.core import AIServiceDep, RequestMetaDep
from app.schemas.ai import AIUsageRead, AnalysisKind, AnalysisRead, AnalysisRequest
from app.schemas.common import error_responses
from app.schemas.pagination import Page, PageParams, page_params

router = APIRouter(tags=["ai"])

_ERRORS = error_responses(401, 403, 404, 409, 422)
CanRead = Annotated[Principal, Depends(require_permission(Permission.FINDINGS_READ))]
CanUse = Annotated[Principal, Depends(require_permission(Permission.AI_USE))]
BASE = "/projects/{project_id}/ai"


@router.get(f"{BASE}/usage", responses=_ERRORS, summary="AI availability and today's usage")
async def usage(project_id: uuid.UUID, principal: CanRead, service: AIServiceDep) -> AIUsageRead:
    return AIUsageRead(**asdict(await service.usage(principal, project_id)))


@router.post(
    f"{BASE}/analyses",
    status_code=status.HTTP_202_ACCEPTED,
    responses=_ERRORS,
    summary="Request an analysis (returns the job; poll until completed)",
)
async def request_analysis(
    project_id: uuid.UUID,
    payload: AnalysisRequest,
    principal: CanUse,
    service: AIServiceDep,
    meta: RequestMetaDep,
) -> AnalysisRead:
    analysis = await service.request(
        principal,
        project_id,
        kind=payload.kind,
        subject_id=payload.subject_id,
        compare_with=payload.compare_with,
        refresh=payload.refresh,
        meta=meta,
    )
    return AnalysisRead.model_validate(analysis)


@router.get(f"{BASE}/analyses", responses=_ERRORS, summary="List analyses")
async def list_analyses(
    project_id: uuid.UUID,
    principal: CanRead,
    service: AIServiceDep,
    params: Annotated[PageParams, Depends(page_params)],
    subject_id: uuid.UUID | None = None,
    kind: AnalysisKind | None = None,
) -> Page[AnalysisRead]:
    rows, total = await service.list(
        principal, project_id, params, subject_id=subject_id, kind=kind
    )
    return Page(
        items=[AnalysisRead.model_validate(r) for r in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )


@router.get(f"{BASE}/analyses/{{analysis_id}}", responses=_ERRORS, summary="Get an analysis")
async def get_analysis(
    project_id: uuid.UUID, analysis_id: uuid.UUID, principal: CanRead, service: AIServiceDep
) -> AnalysisRead:
    return AnalysisRead.model_validate(await service.get(principal, project_id, analysis_id))


@router.post(
    f"{BASE}/analyses/{{analysis_id}}/review",
    responses=_ERRORS,
    summary="Record that a person reviewed this analysis",
)
async def review_analysis(
    project_id: uuid.UUID,
    analysis_id: uuid.UUID,
    principal: CanUse,
    service: AIServiceDep,
    meta: RequestMetaDep,
) -> AnalysisRead:
    analysis = await service.review(principal, project_id, analysis_id, meta)
    return AnalysisRead.model_validate(analysis)
