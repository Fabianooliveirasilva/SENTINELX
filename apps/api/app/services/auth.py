"""Authentication, session and credential lifecycle.

Session model
-------------
* Login creates a *session family* and returns a short-lived JWT access token
  plus an opaque refresh token (HttpOnly cookie). Only the refresh token's
  SHA-256 digest is stored.
* Every refresh rotates the token: the presented token is revoked and linked to
  its replacement. Presenting an already-rotated token is treated as theft
  (refresh token reuse) and revokes the entire family.
* Logout revokes the family. Password change/reset, deactivation and forced
  logout revoke every family and bump ``users.token_version`` so outstanding
  access tokens stop working immediately.

CSRF
----
Cookie-authenticated endpoints (refresh, logout) use a signed double-submit
token: ``nonce.HMAC(secret, family_id + nonce)``. The browser sends it both as a
cookie and an ``X-CSRF-Token`` header, and the signature binds it to the session
family, so a token planted by a sibling (sub)domain cannot be replayed.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import NoReturn, Protocol

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.context import ANONYMOUS, Actor, Principal, RequestMeta
from app.core.errors import (
    AuthenticationError,
    ConflictError,
    CsrfError,
    InvalidRequestError,
    PermissionDeniedError,
)
from app.core.logging import get_logger
from app.core.permissions import Permission, RoleName
from app.core.security.passwords import PasswordService, validate_password_strength
from app.core.security.tokens import (
    AccessTokenService,
    InvalidTokenError,
    IssuedAccessToken,
    generate_opaque_token,
    hash_opaque_token,
    tokens_match,
)
from app.models import PasswordResetToken, RefreshToken, User, UserMfa
from app.repositories.users import UserRepository, normalize_email
from app.services.audit import record_audit
from app.services.email import EmailMessage, EmailSender

logger = get_logger(__name__)

INVALID_CREDENTIALS = "Invalid email or password."
SESSION_EXPIRED = "Your session has expired. Please sign in again."
INVALID_MFA = "Invalid or expired verification code."


class MfaChecker(Protocol):
    async def check_second_factor(self, user_id: uuid.UUID, code: str) -> bool: ...


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class SessionTokens:
    user: User
    access: IssuedAccessToken
    refresh_token: str
    refresh_expires_in: int
    csrf_token: str


@dataclass(frozen=True, slots=True)
class MfaChallenge:
    """Password accepted but a second factor is still required."""

    token: str
    expires_in: int


@dataclass(frozen=True, slots=True)
class SessionInfo:
    family_id: uuid.UUID
    started_at: datetime
    last_used_at: datetime
    expires_at: datetime
    user_agent: str | None
    ip_address: str | None


def principal_from_user(user: User) -> Principal:
    role = RoleName(user.role.name)
    return Principal(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=role,
        permissions=frozenset(Permission(p.code) for p in user.role.permissions),
    )


class CsrfSigner:
    def __init__(self, secret: str) -> None:
        self._key = hashlib.sha256(f"csrf:{secret}".encode()).digest()

    def _sign(self, family_id: uuid.UUID, nonce: str) -> str:
        return hmac.new(self._key, f"{family_id}.{nonce}".encode(), hashlib.sha256).hexdigest()

    def issue(self, family_id: uuid.UUID) -> str:
        nonce = secrets.token_urlsafe(16)
        return f"{nonce}.{self._sign(family_id, nonce)}"

    def verify(self, token: str, family_id: uuid.UUID) -> bool:
        nonce, _, signature = token.partition(".")
        if not nonce or not signature:
            return False
        return tokens_match(self._sign(family_id, nonce), signature)


class AuthService:
    def __init__(
        self,
        session: AsyncSession,
        settings: Settings,
        passwords: PasswordService,
        access_tokens: AccessTokenService,
        email_sender: EmailSender,
    ) -> None:
        self._session = session
        self._settings = settings
        self._passwords = passwords
        self._access_tokens = access_tokens
        self._email = email_sender
        self._users = UserRepository(session)
        self._csrf = CsrfSigner(settings.secret_key.get_secret_value())

    # ------------------------------------------------------------------ login

    async def login(
        self, email: str, password: str, meta: RequestMeta
    ) -> SessionTokens | MfaChallenge:
        now = utcnow()
        user = await self._users.get_by_email(email, for_update=True)

        if user is not None and user.locked_until is not None and user.locked_until > now:
            await self._passwords.verify(None, password)  # keep timing uniform
            await self._fail_login(meta, user, reason="account_locked")

        result = await self._passwords.verify(user.password_hash if user else None, password)

        if user is None:
            await self._fail_login(meta, None, reason="unknown_account")

        if not result.valid:
            user.failed_login_count += 1
            if user.failed_login_count >= self._settings.login_max_failures:
                user.locked_until = now + timedelta(seconds=self._settings.login_lockout_seconds)
                user.failed_login_count = 0
                record_audit(
                    self._session,
                    action="auth.account_locked",
                    actor=ANONYMOUS,
                    meta=meta,
                    target_type="user",
                    target_id=user.id,
                    details={"lockout_seconds": self._settings.login_lockout_seconds},
                )
            await self._fail_login(meta, user, reason="invalid_password")

        if not user.is_active:
            await self._fail_login(meta, user, reason="inactive_account")

        if result.needs_rehash:
            user.password_hash = await self._passwords.hash(password)

        if await self._has_mfa(user.id):
            # The failure counter is kept: wrong second factors accumulate towards the lockout.
            challenge = self._access_tokens.issue_mfa_challenge(user.id, user.token_version)
            record_audit(
                self._session,
                action="auth.login_mfa_challenge",
                actor=Actor(id=user.id, email=user.email),
                meta=meta,
                target_type="user",
                target_id=user.id,
            )
            await self._session.commit()
            return MfaChallenge(token=challenge.token, expires_in=challenge.expires_in)

        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        tokens = await self._start_session(user, meta, now)
        record_audit(
            self._session,
            action="auth.login",
            actor=Actor(id=user.id, email=user.email),
            meta=meta,
            target_type="user",
            target_id=user.id,
        )
        await self._session.commit()
        return tokens

    async def _has_mfa(self, user_id: uuid.UUID) -> bool:
        stmt = select(UserMfa.user_id).where(
            UserMfa.user_id == user_id, UserMfa.confirmed_at.is_not(None)
        )
        return (await self._session.execute(stmt)).first() is not None

    async def verify_mfa(
        self, challenge_token: str, code: str, mfa: MfaChecker, meta: RequestMeta
    ) -> SessionTokens:
        """Second login step: a valid challenge plus a TOTP or recovery code."""
        now = utcnow()
        try:
            claims = self._access_tokens.decode_mfa_challenge(challenge_token)
        except InvalidTokenError as exc:
            raise AuthenticationError(INVALID_MFA) from exc
        user = await self._users.get(claims.user_id, for_update=True)
        if user is None or not user.is_active or user.token_version != claims.token_version:
            raise AuthenticationError(INVALID_MFA)
        if user.locked_until is not None and user.locked_until > now:
            await self._fail_mfa(meta, user, reason="account_locked")
        if not await mfa.check_second_factor(user.id, code):
            user.failed_login_count += 1
            if user.failed_login_count >= self._settings.login_max_failures:
                user.locked_until = now + timedelta(seconds=self._settings.login_lockout_seconds)
                user.failed_login_count = 0
                record_audit(
                    self._session,
                    action="auth.account_locked",
                    actor=ANONYMOUS,
                    meta=meta,
                    target_type="user",
                    target_id=user.id,
                    details={"lockout_seconds": self._settings.login_lockout_seconds},
                )
            await self._fail_mfa(meta, user, reason="invalid_code")
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        tokens = await self._start_session(user, meta, now)
        record_audit(
            self._session,
            action="auth.login",
            actor=Actor(id=user.id, email=user.email),
            meta=meta,
            target_type="user",
            target_id=user.id,
            details={"mfa": True},
        )
        await self._session.commit()
        return tokens

    async def _fail_mfa(self, meta: RequestMeta, user: User, *, reason: str) -> NoReturn:
        record_audit(
            self._session,
            action="auth.login",
            outcome="failure",
            actor=ANONYMOUS,
            meta=meta,
            target_type="user",
            target_id=user.id,
            details={"reason": reason, "stage": "mfa"},
        )
        await self._session.commit()
        raise AuthenticationError(INVALID_MFA)

    async def _fail_login(self, meta: RequestMeta, user: User | None, *, reason: str) -> NoReturn:
        record_audit(
            self._session,
            action="auth.login",
            outcome="failure",
            actor=ANONYMOUS,
            meta=meta,
            target_type="user" if user else None,
            target_id=user.id if user else None,
            details={"reason": reason},
        )
        await self._session.commit()
        raise AuthenticationError(INVALID_CREDENTIALS)

    # ------------------------------------------------------------------ tokens

    async def _start_session(self, user: User, meta: RequestMeta, now: datetime) -> SessionTokens:
        family_id = uuid.uuid4()
        raw, _ = self._new_refresh_token(user, family_id, now, now, meta)
        return self._session_tokens(user, family_id, raw)

    def _new_refresh_token(
        self,
        user: User,
        family_id: uuid.UUID,
        session_started_at: datetime,
        now: datetime,
        meta: RequestMeta,
    ) -> tuple[str, RefreshToken]:
        raw = generate_opaque_token()
        token = RefreshToken(
            id=uuid.uuid4(),
            user_id=user.id,
            family_id=family_id,
            token_hash=hash_opaque_token(raw),
            created_at=now,
            session_started_at=session_started_at,
            expires_at=now + timedelta(seconds=self._settings.refresh_token_ttl_seconds),
            user_agent=meta.user_agent,
            ip_address=meta.ip_address,
        )
        self._session.add(token)
        return raw, token

    def _session_tokens(self, user: User, family_id: uuid.UUID, raw_refresh: str) -> SessionTokens:
        return SessionTokens(
            user=user,
            access=self._access_tokens.issue(user.id, user.token_version),
            refresh_token=raw_refresh,
            refresh_expires_in=self._settings.refresh_token_ttl_seconds,
            csrf_token=self._csrf.issue(family_id),
        )

    async def _load_refresh(self, raw: str) -> RefreshToken | None:
        stmt = (
            select(RefreshToken)
            .where(RefreshToken.token_hash == hash_opaque_token(raw))
            .with_for_update()
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    def _check_csrf(self, token: RefreshToken, cookie: str | None, header: str | None) -> None:
        if not cookie or not header or not tokens_match(cookie, header):
            raise CsrfError
        if not self._csrf.verify(header, token.family_id):
            raise CsrfError

    async def refresh(
        self,
        raw_refresh: str | None,
        *,
        csrf_cookie: str | None,
        csrf_header: str | None,
        meta: RequestMeta,
    ) -> SessionTokens:
        if not raw_refresh:
            raise AuthenticationError(SESSION_EXPIRED)
        now = utcnow()
        token = await self._load_refresh(raw_refresh)
        if token is None:
            raise AuthenticationError(SESSION_EXPIRED)
        self._check_csrf(token, csrf_cookie, csrf_header)

        if token.revoked_at is not None:
            if token.replaced_by_id is not None:
                await self._handle_reuse(token, meta, now)
            raise AuthenticationError(SESSION_EXPIRED)
        if token.expires_at <= now:
            raise AuthenticationError(SESSION_EXPIRED)

        user = await self._users.get(token.user_id)
        if user is None or not user.is_active:
            raise AuthenticationError(SESSION_EXPIRED)

        raw, replacement = self._new_refresh_token(
            user, token.family_id, token.session_started_at, now, meta
        )
        await self._session.flush()
        token.revoked_at = now
        token.replaced_by_id = replacement.id
        tokens = self._session_tokens(user, token.family_id, raw)
        await self._session.commit()
        return tokens

    async def _handle_reuse(self, token: RefreshToken, meta: RequestMeta, now: datetime) -> None:
        await self._session.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == token.family_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        record_audit(
            self._session,
            action="auth.refresh_token_reuse",
            outcome="failure",
            actor=ANONYMOUS,
            meta=meta,
            target_type="user",
            target_id=token.user_id,
            details={"session_family": str(token.family_id)},
        )
        await self._session.commit()
        logger.warning("refresh_token_reuse_detected", user_id=str(token.user_id))

    async def logout(
        self,
        raw_refresh: str | None,
        *,
        csrf_cookie: str | None,
        csrf_header: str | None,
        meta: RequestMeta,
    ) -> None:
        if not raw_refresh:
            return
        token = await self._load_refresh(raw_refresh)
        if token is None:
            return
        self._check_csrf(token, csrf_cookie, csrf_header)
        await self._revoke_family(token.user_id, token.family_id)
        user = await self._users.get(token.user_id)
        record_audit(
            self._session,
            action="auth.logout",
            actor=Actor(id=token.user_id, email=user.email if user else None),
            meta=meta,
            target_type="user",
            target_id=token.user_id,
        )
        await self._session.commit()

    async def authenticate(self, access_token: str) -> Principal:
        try:
            claims = self._access_tokens.decode(access_token)
        except InvalidTokenError as exc:
            raise AuthenticationError("Invalid or expired access token.") from exc
        user = await self._users.get(claims.user_id)
        if user is None or not user.is_active or user.token_version != claims.token_version:
            raise AuthenticationError("Invalid or expired access token.")
        return principal_from_user(user)

    # ------------------------------------------------------------------ sessions

    async def list_sessions(self, user_id: uuid.UUID) -> Sequence[SessionInfo]:
        now = utcnow()
        stmt = (
            select(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > now,
            )
            .order_by(RefreshToken.created_at.desc())
        )
        tokens = (await self._session.execute(stmt)).scalars().all()
        return [
            SessionInfo(
                family_id=t.family_id,
                started_at=t.session_started_at,
                last_used_at=t.created_at,
                expires_at=t.expires_at,
                user_agent=t.user_agent,
                ip_address=t.ip_address,
            )
            for t in tokens
        ]

    async def current_family(self, raw_refresh: str | None) -> uuid.UUID | None:
        if not raw_refresh:
            return None
        stmt = select(RefreshToken.family_id).where(
            RefreshToken.token_hash == hash_opaque_token(raw_refresh)
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def revoke_session(
        self, principal: Principal, family_id: uuid.UUID, meta: RequestMeta
    ) -> bool:
        revoked = await self._revoke_family(principal.user_id, family_id)
        if revoked:
            record_audit(
                self._session,
                action="auth.session_revoked",
                actor=principal.actor,
                meta=meta,
                target_type="session",
                target_id=family_id,
            )
            await self._session.commit()
        return revoked

    async def _revoke_family(self, user_id: uuid.UUID, family_id: uuid.UUID) -> bool:
        result = await self._session.execute(
            update(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.family_id == family_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=utcnow())
        )
        return bool(getattr(result, "rowcount", 0))

    async def revoke_all_sessions(self, user: User) -> None:
        """Revoke every refresh token and invalidate outstanding access tokens."""
        await self._session.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
        user.token_version += 1

    # ------------------------------------------------------------------ passwords

    async def change_password(
        self, principal: Principal, current: str, new: str, meta: RequestMeta
    ) -> None:
        user = await self._users.get(principal.user_id, for_update=True)
        if user is None:  # pragma: no cover - principal was just loaded
            raise AuthenticationError
        if not (await self._passwords.verify(user.password_hash, current)).valid:
            record_audit(
                self._session,
                action="auth.password_changed",
                outcome="failure",
                actor=principal.actor,
                meta=meta,
                target_type="user",
                target_id=user.id,
                details={"reason": "invalid_current_password"},
            )
            await self._session.commit()
            raise InvalidRequestError("The current password is incorrect.")
        await self._set_password(user, new)
        record_audit(
            self._session,
            action="auth.password_changed",
            actor=principal.actor,
            meta=meta,
            target_type="user",
            target_id=user.id,
        )
        await self._session.commit()

    async def _set_password(self, user: User, new_password: str) -> None:
        try:
            validate_password_strength(new_password, email=user.email)
        except ValueError as exc:
            raise InvalidRequestError(str(exc)) from exc
        user.password_hash = await self._passwords.hash(new_password)
        user.password_changed_at = utcnow()
        user.failed_login_count = 0
        user.locked_until = None
        await self.revoke_all_sessions(user)

    async def request_password_reset(self, email: str, meta: RequestMeta) -> None:
        user = await self._users.get_by_email(email)
        if user is None or not user.is_active:
            # Same response either way: never reveal whether an account exists.
            return
        now = utcnow()
        await self._session.execute(
            update(PasswordResetToken)
            .where(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None))
            .values(used_at=now)
        )
        raw = generate_opaque_token()
        self._session.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=hash_opaque_token(raw),
                created_at=now,
                expires_at=now + timedelta(seconds=self._settings.password_reset_ttl_seconds),
            )
        )
        record_audit(
            self._session,
            action="auth.password_reset_requested",
            actor=ANONYMOUS,
            meta=meta,
            target_type="user",
            target_id=user.id,
        )
        await self._session.commit()

        # The token travels in the URL fragment so it is never sent to servers in
        # request lines or Referer headers.
        link = f"{self._settings.frontend_base_url}/reset-password#token={raw}"
        minutes = self._settings.password_reset_ttl_seconds // 60
        await self._email.send(
            EmailMessage(
                to=user.email,
                subject="Reset your SentinelX password",
                body=(
                    f"A password reset was requested for your SentinelX account.\n\n"
                    f"Open this link within {minutes} minutes to choose a new password:\n"
                    f"{link}\n\nIf you did not request this, you can ignore this message."
                ),
            )
        )

    async def confirm_password_reset(
        self, raw_token: str, new_password: str, meta: RequestMeta
    ) -> None:
        now = utcnow()
        stmt = (
            select(PasswordResetToken)
            .where(PasswordResetToken.token_hash == hash_opaque_token(raw_token))
            .with_for_update()
        )
        token = (await self._session.execute(stmt)).scalar_one_or_none()
        user = await self._users.get(token.user_id, for_update=True) if token else None
        if (
            token is None
            or user is None
            or token.used_at is not None
            or token.expires_at <= now
            or not user.is_active
        ):
            raise InvalidRequestError("This password reset link is invalid or has expired.")
        await self._set_password(user, new_password)
        token.used_at = now
        record_audit(
            self._session,
            action="auth.password_reset_completed",
            actor=Actor(id=user.id, email=user.email),
            meta=meta,
            target_type="user",
            target_id=user.id,
        )
        await self._session.commit()

    # ------------------------------------------------------------------ registration

    async def register(
        self, *, email: str, full_name: str, password: str, meta: RequestMeta
    ) -> User:
        if not self._settings.allow_self_registration:
            raise PermissionDeniedError("Self-registration is disabled. Ask an administrator.")
        email = normalize_email(email)
        if await self._users.get_by_email(email) is not None:
            raise ConflictError("An account with this email already exists.")
        try:
            validate_password_strength(password, email=email)
        except ValueError as exc:
            raise InvalidRequestError(str(exc)) from exc
        role = await self._users.get_role(RoleName.VIEWER)
        user = User(
            email=email,
            full_name=full_name.strip(),
            password_hash=await self._passwords.hash(password),
            role_id=role.id,
        )
        self._session.add(user)
        await self._session.flush()
        record_audit(
            self._session,
            action="auth.registered",
            actor=Actor(id=user.id, email=user.email),
            meta=meta,
            target_type="user",
            target_id=user.id,
        )
        await self._session.commit()
        await self._session.refresh(user)
        return user
