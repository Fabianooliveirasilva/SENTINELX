"""User and role persistence queries."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Literal

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import RoleName
from app.models import Role, User
from app.repositories.sql import LIKE_ESCAPE, contains_pattern
from app.schemas.pagination import PageParams

UserSort = Literal[
    "email", "-email", "created_at", "-created_at", "last_login_at", "-last_login_at"
]

_SORT_COLUMNS = {
    "email": User.email,
    "created_at": User.created_at,
    "last_login_at": User.last_login_at,
}


def normalize_email(email: str) -> str:
    return email.strip().lower()


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(
        self, user_id: uuid.UUID, *, for_update: bool = False, reload: bool = False
    ) -> User | None:
        """``reload=True`` overwrites any stale in-session state (e.g. after a role change)."""
        stmt = select(User).where(User.id == user_id)
        if for_update:
            stmt = stmt.with_for_update(of=User)
        if reload:
            stmt = stmt.execution_options(populate_existing=True)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_by_email(self, email: str, *, for_update: bool = False) -> User | None:
        stmt = select(User).where(User.email == normalize_email(email))
        if for_update:
            stmt = stmt.with_for_update(of=User)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def get_role(self, name: RoleName) -> Role:
        role = (
            await self._session.execute(select(Role).where(Role.name == name.value))
        ).scalar_one_or_none()
        if role is None:  # pragma: no cover - seeded by migration 0002
            raise LookupError(f"role {name.value!r} is not seeded; run migrations")
        return role

    async def list_roles(self) -> Sequence[Role]:
        return (await self._session.execute(select(Role).order_by(Role.name))).scalars().all()

    async def count_active_admins(self) -> int:
        stmt = (
            select(func.count())
            .select_from(User)
            .join(Role, Role.id == User.role_id)
            .where(Role.name == RoleName.ADMIN.value, User.is_active.is_(True))
        )
        return int((await self._session.execute(stmt)).scalar_one())

    async def list(
        self,
        params: PageParams,
        *,
        search: str | None = None,
        role: RoleName | None = None,
        is_active: bool | None = None,
        sort: UserSort = "email",
    ) -> tuple[Sequence[User], int]:
        filters = []
        if search:
            pattern = contains_pattern(search)
            filters.append(
                or_(
                    User.email.like(pattern, escape=LIKE_ESCAPE),
                    func.lower(User.full_name).like(pattern, escape=LIKE_ESCAPE),
                )
            )
        if role is not None:
            filters.append(Role.name == role.value)
        if is_active is not None:
            filters.append(User.is_active.is_(is_active))

        base = select(User).join(Role, Role.id == User.role_id).where(*filters)
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(base.subquery()))
            ).scalar_one()
        )
        column = _SORT_COLUMNS[sort.lstrip("-")]
        order = column.desc().nulls_last() if sort.startswith("-") else column.asc().nulls_last()
        rows = (
            (
                await self._session.execute(
                    base.order_by(order, User.id).offset(params.offset).limit(params.page_size)
                )
            )
            .scalars()
            .all()
        )
        return rows, total
