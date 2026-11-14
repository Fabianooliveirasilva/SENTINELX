"""Project findings: list, summary, detail with evidence trail, triage."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.core.context import Principal
from app.core.permissions import Permission
from app.dependencies.auth import require_permission
from app.dependencies.core import FindingServiceDep, RequestMetaDep
from app.schemas.common import error_responses
from app.schemas.findings import (
    FindingDetail,
    FindingOccurrenceRead,
    FindingRead,
    FindingStatus,
    FindingStatusChangeRead,
    FindingStatusUpdate,
    FindingSummary,
    Severity,
)
from app.schemas.pagination import Page, PageParams, page_params
from app.services.findings import FindingFilters

router = APIRouter(prefix="/projects/{project_id}/findings", tags=["findings"])

_ERRORS = error_responses(401, 403, 404, 409, 422)
CanRead = Annotated[Principal, Depends(require_permission(Permission.FINDINGS_READ))]
CanWrite = Annotated[Principal, Depends(require_permission(Permission.FINDINGS_WRITE))]


@router.get("", responses=_ERRORS, summary="List findings (most severe first)")
async def list_findings(
    project_id: uuid.UUID,
    principal: CanRead,
    service: FindingServiceDep,
    params: Annotated[PageParams, Depends(page_params)],
    status_filter: Annotated[FindingStatus | None, Query(alias="status")] = None,
    severity: Severity | None = None,
    asset_id: uuid.UUID | None = None,
    source: Annotated[str | None, Query(pattern=r"^[a-z]{2,32}$")] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
    active: Annotated[bool, Query(description="Only open or acknowledged findings")] = False,
) -> Page[FindingRead]:
    rows, total = await service.list(
        principal,
        project_id,
        params,
        FindingFilters(
            status=status_filter,
            severity=severity,
            asset_id=asset_id,
            source=source,
            search=search,
            active_only=active,
        ),
    )
    return Page(
        items=[FindingRead.model_validate(r) for r in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )


@router.get("/summary", responses=_ERRORS, summary="Finding counts by status and severity")
async def findings_summary(
    project_id: uuid.UUID, principal: CanRead, service: FindingServiceDep
) -> FindingSummary:
    return FindingSummary.model_validate(await service.summary(principal, project_id))


@router.get("/{finding_id}", responses=_ERRORS, summary="Finding with occurrences and history")
async def get_finding(
    project_id: uuid.UUID, finding_id: uuid.UUID, principal: CanRead, service: FindingServiceDep
) -> FindingDetail:
    finding, occurrences, history = await service.get(principal, project_id, finding_id)
    return FindingDetail(
        **FindingRead.model_validate(finding).model_dump(),
        description=finding.description,
        remediation=finding.remediation,
        references=list(finding.references),
        ruleset_version=finding.ruleset_version,
        occurrences=[FindingOccurrenceRead.model_validate(o) for o in occurrences],
        history=[FindingStatusChangeRead.model_validate(h) for h in history],
    )


@router.post("/{finding_id}/status", responses=_ERRORS, summary="Triage: change the status")
async def change_status(
    project_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: FindingStatusUpdate,
    principal: CanWrite,
    service: FindingServiceDep,
    meta: RequestMetaDep,
) -> FindingRead:
    finding = await service.change_status(
        principal,
        project_id,
        finding_id,
        status=payload.status,
        reason=payload.reason,
        meta=meta,
    )
    return FindingRead.model_validate(finding)
