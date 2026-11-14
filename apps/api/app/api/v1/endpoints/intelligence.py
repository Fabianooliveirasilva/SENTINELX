"""Threat intelligence: CVE search/detail, sync status, product sync, project software."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, status
from sqlalchemy import select

from app.core.context import Principal
from app.core.permissions import Permission
from app.dependencies.auth import require_permission
from app.dependencies.core import (
    IntelDispatcherDep,
    IntelServiceDep,
    ProjectServiceDep,
    RequestMetaDep,
    SessionDep,
    SettingsDep,
)
from app.models import SoftwareComponent
from app.schemas.common import error_responses
from app.schemas.intel import (
    CveDetail,
    CveMatchRead,
    CveRead,
    IntelSourceRead,
    IntelStatus,
    ProductSyncRead,
    ProductSyncRequest,
    SoftwareComponentRead,
)
from app.schemas.pagination import Page, PageParams, page_params
from app.services.audit import record_audit
from app.services.intel import CveFilters

router = APIRouter(tags=["intelligence"])

_ERRORS = error_responses(401, 403, 404, 422)
CanRead = Annotated[Principal, Depends(require_permission(Permission.INTELLIGENCE_READ))]
CanManage = Annotated[Principal, Depends(require_permission(Permission.SETTINGS_MANAGE))]
CanReadAssets = Annotated[Principal, Depends(require_permission(Permission.ASSETS_READ))]
Severity = Annotated[str, Query(pattern=r"^(none|low|medium|high|critical)$")]


@router.get("/intelligence/cves", responses=_ERRORS, summary="Search the local CVE store")
async def search_cves(
    _principal: CanRead,
    service: IntelServiceDep,
    params: Annotated[PageParams, Depends(page_params)],
    search: Annotated[str | None, Query(max_length=200)] = None,
    severity: Severity | None = None,
    kev: bool | None = None,
    vendor: Annotated[str | None, Query(max_length=100)] = None,
    product: Annotated[str | None, Query(max_length=100)] = None,
) -> Page[CveRead]:
    rows, total = await service.search(
        params,
        CveFilters(search=search, severity=severity, kev=kev, vendor=vendor, product=product),
    )
    return Page(
        items=[CveRead.model_validate(r) for r in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )


@router.get(
    "/intelligence/cves/{cve_id}", responses=_ERRORS, summary="CVE with affected configurations"
)
async def get_cve(
    cve_id: Annotated[str, Path(pattern=r"^(?i:cve)-\d{4}-\d{4,7}$")],
    _principal: CanRead,
    service: IntelServiceDep,
) -> CveDetail:
    cve, matches = await service.get(cve_id)
    return CveDetail(
        **CveRead.model_validate(cve).model_dump(),
        cvss31_vector=cve.cvss31_vector,
        cvss31_score=cve.cvss31_score,
        cvss40_vector=cve.cvss40_vector,
        cvss40_score=cve.cvss40_score,
        references=list(cve.references),
        kev_due_on=cve.kev_due_on,
        kev_ransomware=cve.kev_ransomware,
        matches=[CveMatchRead.model_validate(m) for m in matches],
    )


@router.get("/intelligence/status", responses=_ERRORS, summary="Feed and product sync status")
async def intel_status(
    _principal: CanRead, service: IntelServiceDep, settings: SettingsDep
) -> IntelStatus:
    data = await service.status()
    return IntelStatus(
        enabled=settings.intel_enabled,
        nvd_api_key_configured=settings.nvd_api_key is not None,
        cves=data["cves"],
        kev_cves=data["kev_cves"],
        sources=[IntelSourceRead.model_validate(s) for s in data["sources"]],
        products=[ProductSyncRead.model_validate(p) for p in data["products"]],
    )


@router.post(
    "/intelligence/products/sync",
    status_code=status.HTTP_202_ACCEPTED,
    responses=_ERRORS,
    summary="Queue an NVD refresh for a vendor:product (administrators)",
)
async def sync_product(
    payload: ProductSyncRequest,
    principal: CanManage,
    service: IntelServiceDep,
    dispatcher: IntelDispatcherDep,
    session: SessionDep,
    meta: RequestMetaDep,
) -> ProductSyncRead:
    row = await service.request_product(payload.vendor, payload.product)
    record_audit(
        session,
        action="intel.product_sync_requested",
        actor=principal.actor,
        meta=meta,
        details={"vendor": row.vendor, "product": row.product},
    )
    await session.commit()
    dispatcher.refresh_products()
    return ProductSyncRead.model_validate(row)


@router.get(
    "/projects/{project_id}/software",
    responses=_ERRORS,
    summary="Software inventory observed on the project's assets",
)
async def project_software(
    project_id: uuid.UUID,
    principal: CanReadAssets,
    projects: ProjectServiceDep,
    session: SessionDep,
    asset_id: uuid.UUID | None = None,
) -> list[SoftwareComponentRead]:
    await projects.get(principal, project_id)
    stmt = select(SoftwareComponent).where(SoftwareComponent.project_id == project_id)
    if asset_id:
        stmt = stmt.where(SoftwareComponent.asset_id == asset_id)
    rows = (
        (
            await session.execute(
                stmt.order_by(SoftwareComponent.name, SoftwareComponent.version).limit(1000)
            )
        )
        .scalars()
        .all()
    )
    return [SoftwareComponentRead.model_validate(r) for r in rows]
