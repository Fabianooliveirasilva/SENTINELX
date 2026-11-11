"""Project queries. Every read is scoped by the calling principal.

Non-admin principals only ever see projects they are members of. Lookups for
projects outside that scope return ``None`` so the API answers 404 rather than
403, avoiding disclosure of other tenants' project identifiers.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import Select, exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import Principal
from app.models import Project, ProjectMember
from app.repositories.sql import LIKE_ESCAPE, contains_pattern
from app.schemas.pagination import PageParams


def _scoped(stmt: Select[Project], principal: Principal) -> Select[Project]:
    if principal.is_admin:
        return stmt
    membership = exists().where(
        ProjectMember.project_id == Project.id, ProjectMember.user_id == principal.user_id
    )
    return stmt.where(membership)


class ProjectRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_for(self, project_id: uuid.UUID, principal: Principal) -> Project | None:
        stmt = _scoped(select(Project).where(Project.id == project_id), principal)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_for(
        self, principal: Principal, params: PageParams, *, search: str | None = None
    ) -> tuple[Sequence[Project], int]:
        stmt = _scoped(select(Project), principal)
        if search:
            stmt = stmt.where(
                func.lower(Project.name).like(contains_pattern(search), escape=LIKE_ESCAPE)
            )
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )
        rows = (
            (
                await self._session.execute(
                    stmt.order_by(Project.name, Project.id)
                    .offset(params.offset)
                    .limit(params.page_size)
                )
            )
            .scalars()
            .all()
        )
        return rows, total

    async def slug_exists(self, slug: str) -> bool:
        stmt = select(exists().where(Project.slug == slug))
        return bool((await self._session.execute(stmt)).scalar_one())

    async def member_counts(self, project_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, int]:
        if not project_ids:
            return {}
        stmt = (
            select(ProjectMember.project_id, func.count())
            .where(ProjectMember.project_id.in_(project_ids))
            .group_by(ProjectMember.project_id)
        )
        return {row[0]: int(row[1]) for row in (await self._session.execute(stmt)).all()}

    async def list_members(self, project_id: uuid.UUID) -> Sequence[ProjectMember]:
        stmt = (
            select(ProjectMember)
            .where(ProjectMember.project_id == project_id)
            .order_by(ProjectMember.created_at)
        )
        return (await self._session.execute(stmt)).scalars().all()

    async def get_member(self, project_id: uuid.UUID, user_id: uuid.UUID) -> ProjectMember | None:
        return await self._session.get(ProjectMember, (project_id, user_id))
