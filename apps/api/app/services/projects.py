"""Project (tenant) management and membership."""

from __future__ import annotations

import re
import secrets
import unicodedata
import uuid
from collections.abc import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import Principal, RequestMeta
from app.core.errors import ConflictError, InvalidRequestError, NotFoundError
from app.models import Project, ProjectMember
from app.repositories.projects import ProjectRepository
from app.repositories.users import UserRepository
from app.services.audit import record_audit

_MAX_SLUG_BASE = 120


def slugify(value: str) -> str:
    ascii_value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_value.lower()).strip("-")
    return slug[:_MAX_SLUG_BASE].strip("-") or "project"


class ProjectService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._projects = ProjectRepository(session)
        self._users = UserRepository(session)

    async def get(self, principal: Principal, project_id: uuid.UUID) -> Project:
        project = await self._projects.get_for(project_id, principal)
        if project is None:
            raise NotFoundError("Project not found.")
        return project

    async def _unique_slug(self, name: str) -> str:
        base = slugify(name)
        slug = base
        while await self._projects.slug_exists(slug):
            slug = f"{base}-{secrets.token_hex(3)}"
        return slug

    async def create(
        self, principal: Principal, *, name: str, description: str, meta: RequestMeta
    ) -> Project:
        project = Project(
            name=name.strip(),
            slug=await self._unique_slug(name),
            description=description.strip(),
            created_by_id=principal.user_id,
        )
        self._session.add(project)
        await self._session.flush()
        self._session.add(
            ProjectMember(
                project_id=project.id, user_id=principal.user_id, added_by_id=principal.user_id
            )
        )
        record_audit(
            self._session,
            action="project.created",
            actor=principal.actor,
            meta=meta,
            target_type="project",
            target_id=project.id,
            project_id=project.id,
            details={"name": project.name},
        )
        await self._session.commit()
        return project

    async def update(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        *,
        name: str | None,
        description: str | None,
        meta: RequestMeta,
    ) -> Project:
        project = await self.get(principal, project_id)
        changed: list[str] = []
        if name is not None and name.strip() != project.name:
            project.name = name.strip()
            changed.append("name")
        if description is not None and description.strip() != project.description:
            project.description = description.strip()
            changed.append("description")
        if changed:
            record_audit(
                self._session,
                action="project.updated",
                actor=principal.actor,
                meta=meta,
                target_type="project",
                target_id=project.id,
                project_id=project.id,
                details={"fields": changed},
            )
        await self._session.commit()
        return project

    async def delete(self, principal: Principal, project_id: uuid.UUID, meta: RequestMeta) -> None:
        project = await self.get(principal, project_id)
        record_audit(
            self._session,
            action="project.deleted",
            actor=principal.actor,
            meta=meta,
            target_type="project",
            target_id=project.id,
            project_id=project.id,
            details={"name": project.name},
        )
        await self._session.delete(project)
        await self._session.commit()

    async def members(self, principal: Principal, project_id: uuid.UUID) -> Sequence[ProjectMember]:
        await self.get(principal, project_id)
        return await self._projects.list_members(project_id)

    async def add_member(
        self, principal: Principal, project_id: uuid.UUID, user_id: uuid.UUID, meta: RequestMeta
    ) -> ProjectMember:
        project = await self.get(principal, project_id)
        user = await self._users.get(user_id)
        if user is None or not user.is_active:
            raise InvalidRequestError("The user does not exist or is inactive.")
        if await self._projects.get_member(project.id, user.id) is not None:
            raise ConflictError("The user is already a member of this project.")
        member = ProjectMember(
            project_id=project.id, user_id=user.id, added_by_id=principal.user_id
        )
        self._session.add(member)
        record_audit(
            self._session,
            action="project.member_added",
            actor=principal.actor,
            meta=meta,
            target_type="user",
            target_id=user.id,
            project_id=project.id,
        )
        await self._session.commit()
        # Load the relationship explicitly: implicit lazy loads are not allowed in async code.
        await self._session.refresh(member, ["user"])
        return member

    async def remove_member(
        self, principal: Principal, project_id: uuid.UUID, user_id: uuid.UUID, meta: RequestMeta
    ) -> None:
        project = await self.get(principal, project_id)
        member = await self._projects.get_member(project.id, user_id)
        if member is None:
            raise NotFoundError("Membership not found.")
        await self._session.delete(member)
        record_audit(
            self._session,
            action="project.member_removed",
            actor=principal.actor,
            meta=meta,
            target_type="user",
            target_id=user_id,
            project_id=project.id,
        )
        await self._session.commit()
