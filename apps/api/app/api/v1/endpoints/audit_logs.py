"""Read-only access to the security audit trail."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query

from app.core.context import Principal
from app.core.permissions import Permission
from app.dependencies.auth import require_permission
from app.dependencies.core import SessionDep
from app.repositories.audit import AuditFilters, AuditLogRepository
from app.schemas.audit import AuditLogRead
from app.schemas.common import error_responses
from app.schemas.pagination import Page, PageParams, page_params

router = APIRouter(prefix="/audit-logs", tags=["audit"])

CanReadAudit = Annotated[Principal, Depends(require_permission(Permission.AUDIT_READ))]
_ERRORS = error_responses(401, 403)


@router.get("", responses=_ERRORS, summary="Search the audit log (newest first)")
async def list_audit_logs(
    _: CanReadAudit,
    session: SessionDep,
    params: Annotated[PageParams, Depends(page_params)],
    action: Annotated[str | None, Query(max_length=100)] = None,
    actor_id: uuid.UUID | None = None,
    project_id: uuid.UUID | None = None,
    outcome: Literal["success", "failure"] | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Page[AuditLogRead]:
    rows, total = await AuditLogRepository(session).list(
        params,
        AuditFilters(
            action=action,
            actor_id=actor_id,
            project_id=project_id,
            outcome=outcome,
            since=since,
            until=until,
        ),
    )
    return Page(
        items=[AuditLogRead.model_validate(r) for r in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )


@router.get("/actions", responses=_ERRORS, summary="Distinct recorded action names")
async def list_audit_actions(_: CanReadAudit, session: SessionDep) -> list[str]:
    return list(await AuditLogRepository(session).distinct_actions())
