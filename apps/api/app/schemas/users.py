"""User administration and role schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr

from app.core.permissions import Permission, RoleName
from app.models import Role, User
from app.schemas.auth import FullName, PasswordInput


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    full_name: FullName
    password: PasswordInput
    role: RoleName = RoleName.VIEWER


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: FullName | None = None
    role: RoleName | None = None
    is_active: bool | None = None


class UserRead(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    role: RoleName
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None
    locked: bool

    @classmethod
    def from_model(cls, user: User, *, now: datetime) -> UserRead:
        return cls(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=RoleName(user.role.name),
            is_active=user.is_active,
            created_at=user.created_at,
            last_login_at=user.last_login_at,
            locked=user.locked_until is not None and user.locked_until > now,
        )


class UserSummary(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    role: RoleName


class RoleRead(BaseModel):
    name: RoleName
    description: str
    permissions: list[Permission]

    @classmethod
    def from_model(cls, role: Role) -> RoleRead:
        return cls(
            name=RoleName(role.name),
            description=role.description,
            permissions=[Permission(p.code) for p in role.permissions],
        )
