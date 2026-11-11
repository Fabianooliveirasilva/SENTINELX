"""Value objects describing who is acting and from where."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from app.core.permissions import Permission, RoleName


@dataclass(frozen=True, slots=True)
class RequestMeta:
    """Client information captured for audit records and rate limiting."""

    ip_address: str | None
    user_agent: str | None
    request_id: str | None


@dataclass(frozen=True, slots=True)
class Actor:
    id: uuid.UUID | None
    email: str | None


ANONYMOUS = Actor(id=None, email=None)


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated user, with permissions resolved from the database."""

    user_id: uuid.UUID
    email: str
    full_name: str
    role: RoleName
    permissions: frozenset[Permission]

    @property
    def is_admin(self) -> bool:
        return self.role is RoleName.ADMIN

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions

    @property
    def actor(self) -> Actor:
        return Actor(id=self.user_id, email=self.email)
