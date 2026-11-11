"""User administration and role catalog endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.core.context import Principal
from app.core.permissions import Permission, RoleName
from app.dependencies.auth import require_permission
from app.dependencies.core import RequestMetaDep, SessionDep, UserServiceDep
from app.repositories.users import UserRepository, UserSort
from app.schemas.common import error_responses
from app.schemas.pagination import Page, PageParams, page_params
from app.schemas.users import RoleRead, UserCreate, UserRead, UserUpdate
from app.services.auth import utcnow
from app.services.users import UserChanges

router = APIRouter(tags=["users"])

_ERRORS = error_responses(401, 403, 404, 409, 422)

CanReadUsers = Annotated[Principal, Depends(require_permission(Permission.USERS_READ))]
CanManageUsers = Annotated[Principal, Depends(require_permission(Permission.USERS_MANAGE))]
CanReadRoles = Annotated[Principal, Depends(require_permission(Permission.ROLES_READ))]


@router.get("/users", responses=_ERRORS, summary="List users")
async def list_users(
    _: CanReadUsers,
    session: SessionDep,
    params: Annotated[PageParams, Depends(page_params)],
    search: Annotated[str | None, Query(max_length=100)] = None,
    role: RoleName | None = None,
    is_active: bool | None = None,
    sort: UserSort = "email",
) -> Page[UserRead]:
    rows, total = await UserRepository(session).list(
        params, search=search, role=role, is_active=is_active, sort=sort
    )
    now = utcnow()
    return Page(
        items=[UserRead.from_model(u, now=now) for u in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )


@router.post(
    "/users", status_code=status.HTTP_201_CREATED, responses=_ERRORS, summary="Create a user"
)
async def create_user(
    payload: UserCreate, actor: CanManageUsers, users: UserServiceDep, meta: RequestMetaDep
) -> UserRead:
    user = await users.create(
        actor,
        email=payload.email,
        full_name=payload.full_name,
        password=payload.password,
        role=payload.role,
        meta=meta,
    )
    return UserRead.from_model(user, now=utcnow())


@router.get("/users/{user_id}", responses=_ERRORS, summary="Get a user")
async def get_user(user_id: uuid.UUID, _: CanReadUsers, users: UserServiceDep) -> UserRead:
    return UserRead.from_model(await users.get(user_id), now=utcnow())


@router.patch("/users/{user_id}", responses=_ERRORS, summary="Update name, role or status")
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    actor: CanManageUsers,
    users: UserServiceDep,
    meta: RequestMetaDep,
) -> UserRead:
    user = await users.update(
        actor,
        user_id,
        UserChanges(full_name=payload.full_name, role=payload.role, is_active=payload.is_active),
        meta,
    )
    return UserRead.from_model(user, now=utcnow())


@router.post(
    "/users/{user_id}/revoke-sessions",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=_ERRORS,
    summary="Sign the user out of every session",
)
async def revoke_user_sessions(
    user_id: uuid.UUID, actor: CanManageUsers, users: UserServiceDep, meta: RequestMetaDep
) -> None:
    await users.revoke_sessions(actor, user_id, meta)


@router.get("/roles", responses=_ERRORS, summary="Roles and their permissions")
async def list_roles(_: CanReadRoles, session: SessionDep) -> list[RoleRead]:
    return [RoleRead.from_model(r) for r in await UserRepository(session).list_roles()]
