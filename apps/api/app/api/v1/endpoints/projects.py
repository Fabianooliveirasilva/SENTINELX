"""Project (tenant) endpoints. Visibility is limited to membership (admins: all)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.core.context import Principal
from app.core.permissions import Permission
from app.dependencies.auth import require_permission
from app.dependencies.core import ProjectServiceDep, RequestMetaDep, SessionDep
from app.models import Project
from app.repositories.projects import ProjectRepository
from app.schemas.common import error_responses
from app.schemas.pagination import Page, PageParams, page_params
from app.schemas.projects import MemberAdd, MemberRead, ProjectCreate, ProjectRead, ProjectUpdate

router = APIRouter(prefix="/projects", tags=["projects"])

_ERRORS = error_responses(401, 403, 404, 409, 422)

CanReadProjects = Annotated[Principal, Depends(require_permission(Permission.PROJECTS_READ))]
CanManageProjects = Annotated[Principal, Depends(require_permission(Permission.PROJECTS_MANAGE))]


def _read(project: Project, member_count: int) -> ProjectRead:
    return ProjectRead(
        id=project.id,
        name=project.name,
        slug=project.slug,
        description=project.description,
        created_at=project.created_at,
        updated_at=project.updated_at,
        member_count=member_count,
    )


async def _with_count(session: SessionDep, project: Project) -> ProjectRead:
    counts = await ProjectRepository(session).member_counts([project.id])
    return _read(project, counts.get(project.id, 0))


@router.get("", responses=_ERRORS, summary="List projects visible to the caller")
async def list_projects(
    principal: CanReadProjects,
    session: SessionDep,
    params: Annotated[PageParams, Depends(page_params)],
    search: Annotated[str | None, Query(max_length=100)] = None,
) -> Page[ProjectRead]:
    repo = ProjectRepository(session)
    rows, total = await repo.list_for(principal, params, search=search)
    counts = await repo.member_counts([p.id for p in rows])
    return Page(
        items=[_read(p, counts.get(p.id, 0)) for p in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )


@router.post("", status_code=status.HTTP_201_CREATED, responses=_ERRORS, summary="Create")
async def create_project(
    payload: ProjectCreate,
    principal: CanManageProjects,
    projects: ProjectServiceDep,
    session: SessionDep,
    meta: RequestMetaDep,
) -> ProjectRead:
    project = await projects.create(
        principal, name=payload.name, description=payload.description, meta=meta
    )
    return await _with_count(session, project)


@router.get("/{project_id}", responses=_ERRORS, summary="Get a project")
async def get_project(
    project_id: uuid.UUID,
    principal: CanReadProjects,
    projects: ProjectServiceDep,
    session: SessionDep,
) -> ProjectRead:
    return await _with_count(session, await projects.get(principal, project_id))


@router.patch("/{project_id}", responses=_ERRORS, summary="Update a project")
async def update_project(
    project_id: uuid.UUID,
    payload: ProjectUpdate,
    principal: CanManageProjects,
    projects: ProjectServiceDep,
    session: SessionDep,
    meta: RequestMetaDep,
) -> ProjectRead:
    project = await projects.update(
        principal, project_id, name=payload.name, description=payload.description, meta=meta
    )
    return await _with_count(session, project)


@router.delete(
    "/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=_ERRORS,
    summary="Delete a project",
)
async def delete_project(
    project_id: uuid.UUID,
    principal: CanManageProjects,
    projects: ProjectServiceDep,
    meta: RequestMetaDep,
) -> None:
    await projects.delete(principal, project_id, meta)


@router.get("/{project_id}/members", responses=_ERRORS, summary="List project members")
async def list_members(
    project_id: uuid.UUID, principal: CanReadProjects, projects: ProjectServiceDep
) -> list[MemberRead]:
    return [MemberRead.from_model(m) for m in await projects.members(principal, project_id)]


@router.post(
    "/{project_id}/members",
    status_code=status.HTTP_201_CREATED,
    responses=_ERRORS,
    summary="Add a member",
)
async def add_member(
    project_id: uuid.UUID,
    payload: MemberAdd,
    principal: CanManageProjects,
    projects: ProjectServiceDep,
    meta: RequestMetaDep,
) -> MemberRead:
    member = await projects.add_member(principal, project_id, payload.user_id, meta)
    return MemberRead.from_model(member)


@router.delete(
    "/{project_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=_ERRORS,
    summary="Remove a member",
)
async def remove_member(
    project_id: uuid.UUID,
    user_id: uuid.UUID,
    principal: CanManageProjects,
    projects: ProjectServiceDep,
    meta: RequestMetaDep,
) -> None:
    await projects.remove_member(principal, project_id, user_id, meta)
