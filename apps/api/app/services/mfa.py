"""TOTP multi-factor authentication: enrolment, confirmation, checks and removal.

* The secret is encrypted at rest (Fernet, key derived from ``SECRET_KEY``).
* A second factor is a TOTP code (each time step usable once) or a single-use
  recovery code; both are checked under a row lock so they cannot be replayed
  concurrently.
* Enrolment and removal require the current password; removal also requires a
  valid second factor. An administrator can reset a user's MFA (audited, all of
  that user's sessions are revoked).
"""

from __future__ import annotations

import hmac
import time
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.context import Principal, RequestMeta
from app.core.errors import ConflictError, InvalidRequestError
from app.core.security import totp
from app.core.security.passwords import PasswordService
from app.core.security.secretbox import PurposeSecretBox, SecretDecryptionError
from app.models import User, UserMfa
from app.repositories.users import UserRepository
from app.services.audit import record_audit
from app.services.auth import utcnow


class MfaService:
    def __init__(
        self, session: AsyncSession, settings: Settings, passwords: PasswordService
    ) -> None:
        self._session = session
        self._settings = settings
        self._passwords = passwords
        self._box = PurposeSecretBox(settings.secret_key.get_secret_value(), "mfa-secrets")

    async def get(self, user_id: uuid.UUID, *, for_update: bool = False) -> UserMfa | None:
        stmt = select(UserMfa).where(UserMfa.user_id == user_id)
        if for_update:
            stmt = stmt.with_for_update()
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def is_enabled(self, user_id: uuid.UUID) -> bool:
        record = await self.get(user_id)
        return record is not None and record.confirmed_at is not None

    async def status(self, principal: Principal) -> tuple[bool, bool, int]:
        record = await self.get(principal.user_id)
        enabled = record is not None and record.confirmed_at is not None
        pending = record is not None and record.confirmed_at is None
        return enabled, pending, len(record.recovery_code_hashes) if enabled and record else 0

    # ------------------------------------------------------------ second factor

    async def check_second_factor(self, user_id: uuid.UUID, code: str) -> bool:
        """Validate and *consume* a TOTP code or a recovery code (row-locked)."""
        record = await self.get(user_id, for_update=True)
        if record is None or record.confirmed_at is None:
            return False
        if await self._consume_totp(record, code):
            return True
        digest = totp.hash_recovery_code(code)
        for stored in record.recovery_code_hashes:
            if hmac.compare_digest(stored, digest):
                record.recovery_code_hashes = [
                    h for h in record.recovery_code_hashes if h != stored
                ]
                return True
        return False

    async def _consume_totp(self, record: UserMfa, code: str) -> bool:
        try:
            secret = self._box.decrypt(record.secret_encrypted)
        except SecretDecryptionError:
            return False
        step = totp.match_step(secret, code, time.time(), after_step=record.last_used_step)
        if step is None:
            return False
        record.last_used_step = step
        return True

    # ------------------------------------------------------------ enrolment

    async def _user(self, user_id: uuid.UUID) -> User:
        user = await UserRepository(self._session).get(user_id)
        if user is None:  # pragma: no cover - the principal was just loaded
            raise InvalidRequestError("User not found.")
        return user

    async def _verify_password(self, user: User, password: str) -> None:
        if not (await self._passwords.verify(user.password_hash, password)).valid:
            raise InvalidRequestError("The current password is incorrect.")

    async def enroll(
        self, principal: Principal, password: str, meta: RequestMeta
    ) -> tuple[str, str]:
        user = await self._user(principal.user_id)
        await self._verify_password(user, password)
        record = await self.get(user.id, for_update=True)
        if record is not None and record.confirmed_at is not None:
            raise ConflictError("Multi-factor authentication is already enabled.")
        secret = totp.new_secret()
        encrypted = self._box.encrypt(secret)
        if record is None:
            self._session.add(UserMfa(user_id=user.id, secret_encrypted=encrypted))
        else:
            record.secret_encrypted = encrypted
            record.last_used_step = -1
        record_audit(
            self._session,
            action="auth.mfa_enrollment_started",
            actor=principal.actor,
            meta=meta,
            target_type="user",
            target_id=user.id,
        )
        await self._session.commit()
        return secret, totp.provisioning_uri(self._settings.app_name, user.email, secret)

    async def confirm(self, principal: Principal, code: str, meta: RequestMeta) -> list[str]:
        record = await self.get(principal.user_id, for_update=True)
        if record is None or record.confirmed_at is not None:
            raise InvalidRequestError("There is no pending MFA enrolment.")
        if not await self._consume_totp(record, code):
            record_audit(
                self._session,
                action="auth.mfa_enabled",
                outcome="failure",
                actor=principal.actor,
                meta=meta,
                target_type="user",
                target_id=principal.user_id,
                details={"reason": "invalid_code"},
            )
            await self._session.commit()
            raise InvalidRequestError("The code is not valid. Check your authenticator's clock.")
        codes = totp.new_recovery_codes()
        record.recovery_code_hashes = [totp.hash_recovery_code(c) for c in codes]
        record.confirmed_at = utcnow()
        record_audit(
            self._session,
            action="auth.mfa_enabled",
            actor=principal.actor,
            meta=meta,
            target_type="user",
            target_id=principal.user_id,
        )
        await self._session.commit()
        return codes

    async def disable(
        self, principal: Principal, password: str, code: str, meta: RequestMeta
    ) -> None:
        user = await self._user(principal.user_id)
        await self._verify_password(user, password)
        if not await self.check_second_factor(user.id, code):
            record_audit(
                self._session,
                action="auth.mfa_disabled",
                outcome="failure",
                actor=principal.actor,
                meta=meta,
                target_type="user",
                target_id=user.id,
                details={"reason": "invalid_code"},
            )
            await self._session.commit()
            raise InvalidRequestError("The code is not valid.")
        await self._delete(user.id)
        record_audit(
            self._session,
            action="auth.mfa_disabled",
            actor=principal.actor,
            meta=meta,
            target_type="user",
            target_id=user.id,
        )
        await self._session.commit()

    async def _delete(self, user_id: uuid.UUID) -> None:
        record = await self.get(user_id, for_update=True)
        if record is not None:
            await self._session.delete(record)

    async def admin_reset(self, actor: Principal, user: User, meta: RequestMeta) -> None:
        """Remove a user's second factor (lost device). Caller revokes the sessions."""
        await self._delete(user.id)
        record_audit(
            self._session,
            action="user.mfa_reset",
            actor=actor.actor,
            meta=meta,
            target_type="user",
            target_id=user.id,
        )
