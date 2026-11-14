"""Dashboard overview (all accessible projects, or one)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.context import Principal
from app.core.permissions import Permission
from app.dependencies.auth import require_permission
from app.dependencies.core import SessionDep
from app.schemas.common import error_responses
from app.schemas.dashboard import DashboardRead
from app.services.dashboard import build_dashboard

router = APIRouter(tags=["dashboard"])

CanRead = Annotated[Principal, Depends(require_permission(Permission.PROJECTS_READ))]


@router.get(
    "/dashboard",
    responses=error_responses(401, 403, 404, 422),
    summary="Security overview of the projects the caller can access",
)
async def dashboard(
    principal: CanRead, session: SessionDep, project_id: uuid.UUID | None = None
) -> DashboardRead:
    return DashboardRead.model_validate(await build_dashboard(session, principal, project_id))
