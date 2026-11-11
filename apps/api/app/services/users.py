"""User administration (requires ``users:manage``; enforced at the API layer)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import Principal, RequestMeta
from app.core.errors import ConflictError, InvalidRequestError, NotFoundError
from app.core.permissions import RoleName
from app.core.security.passwords import PasswordService, validate_password_strength
from app.models import User
from app.repositories.users import UserRepository, normalize_email
from app.services.audit import record_audit
from app.services.auth import AuthService


@dataclass(frozen=True, slots=True)
class UserChanges:
    full_name: str | None = None
    role: RoleName | None = None
    is_active: bool | None = None


class UserService:
    def __init__(
        self, session: AsyncSession, passwords: PasswordService, auth: AuthService
    ) -> None:
        self._session = session
        self._passwords = passwords
        self._auth = auth
        self._users = UserRepository(session)

    async def get(self, user_id: uuid.UUID, *, reload: bool = False) -> User:
        user = await self._users.get(user_id, reload=reload)
        if user is None:
            raise NotFoundError("User not found.")
        return user

    async def create(
        self,
        actor: Principal,
        *,
        email: str,
        full_name: str,
        password: str,
        role: RoleName,
        meta: RequestMeta,
    ) -> User:
        email = normalize_email(email)
        if await self._users.get_by_email(email) is not None:
            raise ConflictError("An account with this email already exists.")
        try:
            validate_password_strength(password, email=email)
        except ValueError as exc:
            raise InvalidRequestError(str(exc)) from exc

        user = User(
            email=email,
            full_name=full_name.strip(),
            password_hash=await self._passwords.hash(password),
            role_id=(await self._users.get_role(role)).id,
        )
        self._session.add(user)
        await self._session.flush()
        record_audit(
            self._session,
            action="user.created",
            actor=actor.actor,
            meta=meta,
            target_type="user",
            target_id=user.id,
            details={"role": role.value},
        )
        await self._session.commit()
        return await self.get(user.id)

    async def update(
        self, actor: Principal, user_id: uuid.UUID, changes: UserChanges, meta: RequestMeta
    ) -> User:
        user = await self._users.get(user_id, for_update=True)
        if user is None:
            raise NotFoundError("User not found.")

        current_role = RoleName(user.role.name)
        demoting_admin = (
            current_role is RoleName.ADMIN
            and changes.role is not None
            and changes.role is not RoleName.ADMIN
        )
        deactivating = changes.is_active is False and user.is_active

        if user.id == actor.user_id and (demoting_admin or deactivating):
            raise InvalidRequestError("You cannot demote or deactivate your own account.")
        if (
            demoting_admin or (deactivating and current_role is RoleName.ADMIN)
        ) and await self._users.count_active_admins() <= 1:
            raise InvalidRequestError("At least one active administrator must remain.")

        audit_changes: dict[str, object] = {}
        if changes.full_name is not None and changes.full_name.strip() != user.full_name:
            user.full_name = changes.full_name.strip()
            audit_changes["full_name"] = True
        if changes.role is not None and changes.role is not current_role:
            user.role_id = (await self._users.get_role(changes.role)).id
            audit_changes["role"] = {"from": current_role.value, "to": changes.role.value}
        if changes.is_active is not None and changes.is_active != user.is_active:
            user.is_active = changes.is_active
            audit_changes["is_active"] = changes.is_active
            if not changes.is_active:
                await self._auth.revoke_all_sessions(user)

        if audit_changes:
            record_audit(
                self._session,
                action="user.updated",
                actor=actor.actor,
                meta=meta,
                target_type="user",
                target_id=user.id,
                details=audit_changes,
            )
        await self._session.commit()
        return await self.get(user_id, reload=True)

    async def revoke_sessions(
        self, actor: Principal, user_id: uuid.UUID, meta: RequestMeta
    ) -> None:
        user = await self._users.get(user_id, for_update=True)
        if user is None:
            raise NotFoundError("User not found.")
        await self._auth.revoke_all_sessions(user)
        record_audit(
            self._session,
            action="user.sessions_revoked",
            actor=actor.actor,
            meta=meta,
            target_type="user",
            target_id=user.id,
        )
        await self._session.commit()
