"""Reports: request (202 + job), list, download, delete."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from app.core.context import Principal
from app.core.permissions import Permission
from app.dependencies.auth import require_permission
from app.dependencies.core import ReportServiceDep, RequestMetaDep
from app.schemas.common import error_responses
from app.schemas.pagination import Page, PageParams, page_params
from app.schemas.reports import ReportCreate, ReportRead
from app.services.reports import MEDIA_TYPES, filename

router = APIRouter(tags=["reports"])

_ERRORS = error_responses(401, 403, 404, 409, 422)
CanRead = Annotated[Principal, Depends(require_permission(Permission.REPORTS_READ))]
CanGenerate = Annotated[Principal, Depends(require_permission(Permission.REPORTS_GENERATE))]
BASE = "/projects/{project_id}/reports"


@router.post(
    BASE,
    status_code=status.HTTP_202_ACCEPTED,
    responses=_ERRORS,
    summary="Request a PDF or JSON report (returns the job; poll until completed)",
)
async def request_report(
    project_id: uuid.UUID,
    payload: ReportCreate,
    principal: CanGenerate,
    service: ReportServiceDep,
    meta: RequestMetaDep,
) -> ReportRead:
    report = await service.request(
        principal,
        project_id,
        scope=payload.scope,
        scan_job_id=payload.scan_job_id,
        fmt=payload.format,
        title=payload.title,
        include_resolved=payload.include_resolved,
        include_ai=payload.include_ai,
        include_evidence=payload.include_evidence,
        meta=meta,
    )
    return ReportRead.model_validate(report)


@router.get(BASE, responses=_ERRORS, summary="List reports")
async def list_reports(
    project_id: uuid.UUID,
    principal: CanRead,
    service: ReportServiceDep,
    params: Annotated[PageParams, Depends(page_params)],
) -> Page[ReportRead]:
    rows, total = await service.list(principal, project_id, params)
    return Page(
        items=[ReportRead.model_validate(r) for r in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )


@router.get(f"{BASE}/{{report_id}}", responses=_ERRORS, summary="Get a report's status")
async def get_report(
    project_id: uuid.UUID, report_id: uuid.UUID, principal: CanRead, service: ReportServiceDep
) -> ReportRead:
    return ReportRead.model_validate(await service.get(principal, project_id, report_id))


@router.get(
    f"{BASE}/{{report_id}}/download",
    responses={**_ERRORS, 200: {"content": {"application/pdf": {}, "application/json": {}}}},
    summary="Download a completed report (audited)",
    response_class=Response,
)
async def download_report(
    project_id: uuid.UUID,
    report_id: uuid.UUID,
    principal: CanRead,
    service: ReportServiceDep,
    meta: RequestMetaDep,
) -> Response:
    report = await service.download(principal, project_id, report_id, meta)
    return Response(
        content=report.content,
        media_type=MEDIA_TYPES[report.format],
        headers={
            "Content-Disposition": f'attachment; filename="{filename(report)}"',
            "X-Content-SHA256": report.sha256 or "",
            "Cache-Control": "no-store",
        },
    )


@router.delete(
    f"{BASE}/{{report_id}}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=_ERRORS,
    summary="Delete a report",
)
async def delete_report(
    project_id: uuid.UUID,
    report_id: uuid.UUID,
    principal: CanGenerate,
    service: ReportServiceDep,
    meta: RequestMetaDep,
) -> None:
    await service.delete(principal, project_id, report_id, meta)
