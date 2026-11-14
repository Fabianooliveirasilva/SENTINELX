"""Scan orchestration: catalog, jobs (202 + job id), cancellation and emergency stop."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.core.context import Principal
from app.core.permissions import Permission
from app.dependencies.auth import require_permission
from app.dependencies.core import RequestMetaDep, ScanServiceDep
from app.schemas.common import error_responses
from app.schemas.pagination import Page, PageParams, page_params
from app.schemas.scans import (
    EmergencyStopRequest,
    EmergencyStopResult,
    ScanControlsRead,
    ScanCreate,
    ScanJobDetail,
    ScanJobRead,
    ScannerId,
    ScannerRead,
    ScanStatus,
    scanner_catalog,
)
from app.services.scans import ScanFilters

router = APIRouter(tags=["scans"])

_ERRORS = error_responses(401, 403, 404, 409, 422)
CanRead = Annotated[Principal, Depends(require_permission(Permission.SCANS_READ))]
CanExecute = Annotated[Principal, Depends(require_permission(Permission.SCANS_EXECUTE))]
CanManage = Annotated[Principal, Depends(require_permission(Permission.SETTINGS_MANAGE))]


@router.get("/scanners", responses=_ERRORS, summary="Available scanners and safe profiles")
async def list_scanners(_principal: CanRead) -> list[ScannerRead]:
    return scanner_catalog()


@router.get("/scans/controls", responses=_ERRORS, summary="Platform scan controls")
async def get_controls(_principal: CanRead, service: ScanServiceDep) -> ScanControlsRead:
    return ScanControlsRead.from_domain(await service.controls())


@router.post(
    "/scans/emergency-stop",
    responses=_ERRORS,
    summary="Halt all scanning and cancel every active job (administrators)",
)
async def emergency_stop(
    payload: EmergencyStopRequest,
    principal: CanManage,
    service: ScanServiceDep,
    meta: RequestMetaDep,
) -> EmergencyStopResult:
    cancelled = await service.emergency_stop(principal, payload.reason, meta)
    controls = ScanControlsRead.from_domain(await service.controls())
    return EmergencyStopResult(**controls.model_dump(), cancelled_jobs=cancelled)


@router.post("/scans/resume", responses=_ERRORS, summary="Lift an emergency stop")
async def resume(
    principal: CanManage, service: ScanServiceDep, meta: RequestMetaDep
) -> ScanControlsRead:
    await service.resume(principal, meta)
    return ScanControlsRead.from_domain(await service.controls())


@router.get("/projects/{project_id}/scans", responses=_ERRORS, summary="List scan jobs")
async def list_scans(
    project_id: uuid.UUID,
    principal: CanRead,
    service: ScanServiceDep,
    params: Annotated[PageParams, Depends(page_params)],
    status_filter: Annotated[ScanStatus | None, Query(alias="status")] = None,
    asset_id: uuid.UUID | None = None,
    scanner: ScannerId | None = None,
) -> Page[ScanJobRead]:
    rows, total = await service.list(
        principal,
        project_id,
        params,
        ScanFilters(status=status_filter, asset_id=asset_id, scanner=scanner),
    )
    return Page(
        items=[ScanJobRead.model_validate(r) for r in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )


@router.post(
    "/projects/{project_id}/scans",
    status_code=status.HTTP_202_ACCEPTED,
    responses={**_ERRORS, **error_responses(429, 503)},
    summary="Request a scan of an authorized asset (asynchronous)",
)
async def request_scan(
    project_id: uuid.UUID,
    payload: ScanCreate,
    principal: CanExecute,
    service: ScanServiceDep,
    meta: RequestMetaDep,
) -> ScanJobRead:
    job = await service.request(
        principal,
        project_id,
        asset_id=payload.asset_id,
        scanner_name=payload.scanner,
        profile=payload.profile,
        meta=meta,
    )
    return ScanJobRead.model_validate(job)


@router.get(
    "/projects/{project_id}/scans/{scan_id}",
    responses=_ERRORS,
    summary="Scan job with scope decision, results and evidence",
)
async def get_scan(
    project_id: uuid.UUID, scan_id: uuid.UUID, principal: CanRead, service: ScanServiceDep
) -> ScanJobDetail:
    return ScanJobDetail.from_model(await service.get(principal, project_id, scan_id, detail=True))


@router.post(
    "/projects/{project_id}/scans/{scan_id}/cancel",
    responses=_ERRORS,
    summary="Cancel a pending, queued or running scan",
)
async def cancel_scan(
    project_id: uuid.UUID,
    scan_id: uuid.UUID,
    principal: CanExecute,
    service: ScanServiceDep,
    meta: RequestMetaDep,
) -> ScanJobRead:
    return ScanJobRead.model_validate(await service.cancel(principal, project_id, scan_id, meta))
