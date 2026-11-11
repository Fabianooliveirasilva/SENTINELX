"""Project-scoped asset inventory, authorizations and scope checks."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.core.context import Principal
from app.core.permissions import Permission
from app.dependencies.auth import require_permission
from app.dependencies.core import AssetServiceDep, RateLimiterDep, RequestMetaDep, SettingsDep
from app.models import Asset
from app.schemas.assets import (
    AssetCreate,
    AssetDetail,
    AssetRead,
    AssetStatus,
    AssetUpdate,
    AuthorizationCreate,
    AuthorizationRead,
    Criticality,
    RevokeAuthorization,
    ScopeCheckRequest,
    ScopeDecisionRead,
)
from app.schemas.audit import AuditLogRead
from app.schemas.common import error_responses
from app.schemas.pagination import Page, PageParams, page_params
from app.services.assets import AssetFilters, AssetService, NewAuthorization, utcnow
from sentinelx_security.scope import AssetType

router = APIRouter(prefix="/projects/{project_id}", tags=["assets"])

_ERRORS = error_responses(401, 403, 404, 409, 422)
CanRead = Annotated[Principal, Depends(require_permission(Permission.ASSETS_READ))]
CanWrite = Annotated[Principal, Depends(require_permission(Permission.ASSETS_WRITE))]


def _detail(service: AssetService, asset: Asset) -> AssetDetail:
    now = utcnow()
    base = AssetRead.from_model(asset, service.eligibility(asset, now), now=now)
    return AssetDetail(
        **base.model_dump(),
        authorizations=[AuthorizationRead.from_model(a, now=now) for a in asset.authorizations],
    )


@router.get("/assets", responses=_ERRORS, summary="List assets in a project")
async def list_assets(
    project_id: uuid.UUID,
    principal: CanRead,
    service: AssetServiceDep,
    params: Annotated[PageParams, Depends(page_params)],
    type: AssetType | None = None,
    status_filter: Annotated[AssetStatus | None, Query(alias="status")] = None,
    criticality: Criticality | None = None,
    tag: Annotated[str | None, Query(max_length=50)] = None,
    search: Annotated[str | None, Query(max_length=200)] = None,
) -> Page[AssetRead]:
    rows, total = await service.list(
        principal,
        project_id,
        params,
        AssetFilters(
            type=type, status=status_filter, criticality=criticality, tag=tag, search=search
        ),
    )
    now = utcnow()
    return Page(
        items=[AssetRead.from_model(a, service.eligibility(a, now), now=now) for a in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )


@router.post(
    "/assets", status_code=status.HTTP_201_CREATED, responses=_ERRORS, summary="Register an asset"
)
async def create_asset(
    project_id: uuid.UUID,
    payload: AssetCreate,
    principal: CanWrite,
    service: AssetServiceDep,
    meta: RequestMetaDep,
) -> AssetDetail:
    asset = await service.create(
        principal,
        project_id,
        asset_type=payload.type,
        value=payload.value,
        description=payload.description,
        tags=payload.tags,
        criticality=payload.criticality,
        exposure=payload.exposure,
        meta=meta,
    )
    return _detail(service, asset)


@router.get("/assets/{asset_id}", responses=_ERRORS, summary="Asset with authorizations")
async def get_asset(
    project_id: uuid.UUID, asset_id: uuid.UUID, principal: CanRead, service: AssetServiceDep
) -> AssetDetail:
    return _detail(service, await service.get(principal, project_id, asset_id))


@router.patch("/assets/{asset_id}", responses=_ERRORS, summary="Update or archive an asset")
async def update_asset(
    project_id: uuid.UUID,
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    principal: CanWrite,
    service: AssetServiceDep,
    meta: RequestMetaDep,
) -> AssetDetail:
    changes = payload.model_dump(exclude_unset=True, exclude_none=True)
    asset = await service.update(principal, project_id, asset_id, changes, meta)
    return _detail(service, asset)


@router.get("/assets/{asset_id}/history", responses=_ERRORS, summary="Change history")
async def asset_history(
    project_id: uuid.UUID, asset_id: uuid.UUID, principal: CanRead, service: AssetServiceDep
) -> list[AuditLogRead]:
    return [
        AuditLogRead.model_validate(e)
        for e in await service.history(principal, project_id, asset_id)
    ]


@router.post(
    "/assets/{asset_id}/authorizations",
    status_code=status.HTTP_201_CREATED,
    responses=_ERRORS,
    summary="Record an authorization to test this asset",
)
async def add_authorization(
    project_id: uuid.UUID,
    asset_id: uuid.UUID,
    payload: AuthorizationCreate,
    principal: CanWrite,
    service: AssetServiceDep,
    meta: RequestMetaDep,
) -> AuthorizationRead:
    authorization = await service.add_authorization(
        principal,
        project_id,
        asset_id,
        NewAuthorization(**payload.model_dump()),
        meta,
    )
    return AuthorizationRead.from_model(authorization, now=utcnow())


@router.post(
    "/assets/{asset_id}/authorizations/{authorization_id}/revoke",
    responses=_ERRORS,
    summary="Revoke an authorization",
)
async def revoke_authorization(
    project_id: uuid.UUID,
    asset_id: uuid.UUID,
    authorization_id: uuid.UUID,
    payload: RevokeAuthorization,
    principal: CanWrite,
    service: AssetServiceDep,
    meta: RequestMetaDep,
) -> AuthorizationRead:
    authorization = await service.revoke_authorization(
        principal, project_id, asset_id, authorization_id, payload.reason, meta
    )
    return AuthorizationRead.from_model(authorization, now=utcnow())


@router.post(
    "/scope/check",
    responses={**_ERRORS, **error_responses(429)},
    summary="Explain whether a target is in scope (no traffic is sent to the target)",
)
async def scope_check(
    project_id: uuid.UUID,
    payload: ScopeCheckRequest,
    principal: CanRead,
    service: AssetServiceDep,
    limiter: RateLimiterDep,
    settings: SettingsDep,
) -> ScopeDecisionRead:
    # The check may perform DNS lookups, so it is rate limited per user.
    await limiter.enforce(
        "scope-check:user",
        str(principal.user_id),
        limit=settings.rate_limit_scope_check_per_minute,
        window_seconds=60,
    )
    decision = await service.scope_check(principal, project_id, payload.target, payload.technique)
    return ScopeDecisionRead.from_domain(decision)
