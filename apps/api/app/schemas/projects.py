"""Project and membership schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from app.core.permissions import RoleName
from app.models import ProjectMember

ProjectName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
Description = Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000)]


class ProjectCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: ProjectName
    description: Description = ""


class ProjectUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: ProjectName | None = None
    description: Description | None = None


class ProjectRead(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    description: str
    created_at: datetime
    updated_at: datetime
    member_count: int


class MemberAdd(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: uuid.UUID


class MemberRead(BaseModel):
    user_id: uuid.UUID
    email: str
    full_name: str
    role: RoleName
    is_active: bool
    added_at: datetime

    @classmethod
    def from_model(cls, member: ProjectMember) -> MemberRead:
        return cls(
            user_id=member.user_id,
            email=member.user.email,
            full_name=member.user.full_name,
            role=RoleName(member.user.role.name),
            is_active=member.user.is_active,
            added_at=member.created_at,
        )
