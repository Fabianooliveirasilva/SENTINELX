"""Authentication endpoints.

Cookies
* ``sentinelx_refresh`` — opaque refresh token. HttpOnly, Secure, SameSite=Strict,
  scoped to ``/api/v1/auth`` so it is only ever sent to these endpoints.
* ``sentinelx_csrf`` — signed CSRF token readable by the SPA, which echoes it in
  the ``X-CSRF-Token`` header for cookie-authenticated requests.

The access token is returned in the response body and kept in memory by the SPA.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Final

from fastapi import APIRouter, Cookie, Header, Response, status

from app.core.config import Settings
from app.core.errors import NotFoundError
from app.core.security.tokens import hash_opaque_token
from app.dependencies.auth import CurrentPrincipal
from app.dependencies.core import (
    AuthServiceDep,
    MfaServiceDep,
    RateLimiterDep,
    RequestMetaDep,
    SettingsDep,
)
from app.schemas.auth import (
    ChangePasswordRequest,
    CurrentUser,
    LoginRequest,
    MessageResponse,
    MfaChallengeResponse,
    MfaConfirmRequest,
    MfaDisableRequest,
    MfaEnrollment,
    MfaEnrollRequest,
    MfaRecoveryCodes,
    MfaStatus,
    MfaVerifyRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    RegisterRequest,
    SessionRead,
    TokenResponse,
)
from app.schemas.common import error_responses
from app.schemas.users import UserRead
from app.services.auth import MfaChallenge, SessionTokens, principal_from_user, utcnow

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE: Final = "sentinelx_refresh"
CSRF_COOKIE: Final = "sentinelx_csrf"
CSRF_HEADER: Final = "X-CSRF-Token"
REFRESH_COOKIE_PATH: Final = "/api/v1/auth"
_MINUTE: Final = 60
_HOUR: Final = 3600

_ERRORS = error_responses(401, 403, 422, 429)


def _set_session_cookies(response: Response, tokens: SessionTokens, settings: Settings) -> None:
    response.set_cookie(
        REFRESH_COOKIE,
        tokens.refresh_token,
        max_age=tokens.refresh_expires_in,
        path=REFRESH_COOKIE_PATH,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )
    response.set_cookie(
        CSRF_COOKIE,
        tokens.csrf_token,
        max_age=tokens.refresh_expires_in,
        path="/",
        secure=settings.cookie_secure,
        httponly=False,
        samesite="strict",
    )


def _clear_session_cookies(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        REFRESH_COOKIE,
        path=REFRESH_COOKIE_PATH,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )
    response.delete_cookie(
        CSRF_COOKIE, path="/", secure=settings.cookie_secure, httponly=False, samesite="strict"
    )


def _token_response(tokens: SessionTokens) -> TokenResponse:
    principal = principal_from_user(tokens.user)
    return TokenResponse(
        access_token=tokens.access.token,
        expires_in=tokens.access.expires_in,
        user=CurrentUser(
            id=principal.user_id,
            email=principal.email,
            full_name=principal.full_name,
            role=principal.role,
            permissions=sorted(principal.permissions),
        ),
    )


@router.post("/login", responses=_ERRORS, summary="Sign in with email and password")
async def login(
    payload: LoginRequest,
    response: Response,
    auth: AuthServiceDep,
    limiter: RateLimiterDep,
    meta: RequestMetaDep,
    settings: SettingsDep,
) -> TokenResponse | MfaChallengeResponse:
    limit = settings.rate_limit_login_per_minute
    await limiter.enforce(
        "login:ip", meta.ip_address or "unknown", limit=limit, window_seconds=_MINUTE
    )
    await limiter.enforce(
        "login:account", payload.email.lower(), limit=limit, window_seconds=_MINUTE
    )
    result = await auth.login(payload.email, payload.password, meta)
    if isinstance(result, MfaChallenge):
        return MfaChallengeResponse(challenge_token=result.token, expires_in=result.expires_in)
    _set_session_cookies(response, result, settings)
    return _token_response(result)


@router.post(
    "/mfa/verify",
    responses=_ERRORS,
    summary="Finish signing in with a TOTP or recovery code",
)
async def verify_mfa(
    payload: MfaVerifyRequest,
    response: Response,
    auth: AuthServiceDep,
    mfa: MfaServiceDep,
    limiter: RateLimiterDep,
    meta: RequestMetaDep,
    settings: SettingsDep,
) -> TokenResponse:
    limit = settings.rate_limit_login_per_minute
    await limiter.enforce(
        "mfa:ip", meta.ip_address or "unknown", limit=limit, window_seconds=_MINUTE
    )
    # The challenge token is the account identity here; bucket on its digest so a
    # stolen challenge cannot be guessed against without limit.
    await limiter.enforce(
        "mfa:challenge",
        hash_opaque_token(payload.challenge_token),
        limit=settings.rate_limit_mfa_per_challenge,
        window_seconds=_MINUTE * 5,
    )
    tokens = await auth.verify_mfa(payload.challenge_token, payload.code, mfa, meta)
    _set_session_cookies(response, tokens, settings)
    return _token_response(tokens)


@router.get("/mfa", responses=_ERRORS, summary="Multi-factor authentication status")
async def mfa_status(principal: CurrentPrincipal, mfa: MfaServiceDep) -> MfaStatus:
    enabled, pending, remaining = await mfa.status(principal)
    return MfaStatus(
        enabled=enabled, pending_enrollment=pending, recovery_codes_remaining=remaining
    )


@router.post("/mfa/enroll", responses=_ERRORS, summary="Start TOTP enrolment (needs the password)")
async def mfa_enroll(
    payload: MfaEnrollRequest,
    principal: CurrentPrincipal,
    mfa: MfaServiceDep,
    limiter: RateLimiterDep,
    meta: RequestMetaDep,
    settings: SettingsDep,
) -> MfaEnrollment:
    await limiter.enforce(
        "mfa:enroll",
        str(principal.user_id),
        limit=settings.rate_limit_mfa_per_challenge,
        window_seconds=_MINUTE * 5,
    )
    secret, uri = await mfa.enroll(principal, payload.password, meta)
    return MfaEnrollment(secret=secret, otpauth_uri=uri)


@router.post(
    "/mfa/confirm", responses=_ERRORS, summary="Confirm enrolment; returns recovery codes once"
)
async def mfa_confirm(
    payload: MfaConfirmRequest,
    principal: CurrentPrincipal,
    mfa: MfaServiceDep,
    limiter: RateLimiterDep,
    meta: RequestMetaDep,
    settings: SettingsDep,
) -> MfaRecoveryCodes:
    await limiter.enforce(
        "mfa:confirm",
        str(principal.user_id),
        limit=settings.rate_limit_mfa_per_challenge,
        window_seconds=_MINUTE * 5,
    )
    return MfaRecoveryCodes(recovery_codes=await mfa.confirm(principal, payload.code, meta))


@router.post(
    "/mfa/disable",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=_ERRORS,
    summary="Turn MFA off (needs the password and a valid code)",
)
async def mfa_disable(
    payload: MfaDisableRequest,
    principal: CurrentPrincipal,
    mfa: MfaServiceDep,
    limiter: RateLimiterDep,
    meta: RequestMetaDep,
    settings: SettingsDep,
) -> None:
    await limiter.enforce(
        "mfa:disable",
        str(principal.user_id),
        limit=settings.rate_limit_mfa_per_challenge,
        window_seconds=_MINUTE * 5,
    )
    await mfa.disable(principal, payload.password, payload.code, meta)


@router.post("/refresh", responses=_ERRORS, summary="Rotate the refresh token")
async def refresh(
    response: Response,
    auth: AuthServiceDep,
    limiter: RateLimiterDep,
    meta: RequestMetaDep,
    settings: SettingsDep,
    refresh_cookie: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
    csrf_cookie: Annotated[str | None, Cookie(alias=CSRF_COOKIE)] = None,
    csrf_header: Annotated[str | None, Header(alias=CSRF_HEADER)] = None,
) -> TokenResponse:
    await limiter.enforce(
        "refresh:ip",
        meta.ip_address or "unknown",
        limit=settings.rate_limit_refresh_per_minute,
        window_seconds=_MINUTE,
    )
    tokens = await auth.refresh(
        refresh_cookie, csrf_cookie=csrf_cookie, csrf_header=csrf_header, meta=meta
    )
    _set_session_cookies(response, tokens, settings)
    return _token_response(tokens)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=_ERRORS,
    summary="Sign out and revoke the current session",
)
async def logout(
    response: Response,
    auth: AuthServiceDep,
    meta: RequestMetaDep,
    settings: SettingsDep,
    refresh_cookie: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
    csrf_cookie: Annotated[str | None, Cookie(alias=CSRF_COOKIE)] = None,
    csrf_header: Annotated[str | None, Header(alias=CSRF_HEADER)] = None,
) -> None:
    await auth.logout(refresh_cookie, csrf_cookie=csrf_cookie, csrf_header=csrf_header, meta=meta)
    _clear_session_cookies(response, settings)


@router.get("/me", responses=_ERRORS, summary="The authenticated user and permissions")
async def me(principal: CurrentPrincipal) -> CurrentUser:
    return CurrentUser(
        id=principal.user_id,
        email=principal.email,
        full_name=principal.full_name,
        role=principal.role,
        permissions=sorted(principal.permissions),
    )


@router.post(
    "/change-password",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=_ERRORS,
    summary="Change password (signs out every session)",
)
async def change_password(
    payload: ChangePasswordRequest,
    response: Response,
    principal: CurrentPrincipal,
    auth: AuthServiceDep,
    meta: RequestMetaDep,
    settings: SettingsDep,
) -> None:
    await auth.change_password(principal, payload.current_password, payload.new_password, meta)
    _clear_session_cookies(response, settings)


@router.get("/sessions", responses=_ERRORS, summary="Active sessions of the current user")
async def list_sessions(
    principal: CurrentPrincipal,
    auth: AuthServiceDep,
    refresh_cookie: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
) -> list[SessionRead]:
    current = await auth.current_family(refresh_cookie)
    return [
        SessionRead(
            id=s.family_id,
            started_at=s.started_at,
            last_used_at=s.last_used_at,
            expires_at=s.expires_at,
            user_agent=s.user_agent,
            ip_address=s.ip_address,
            current=s.family_id == current,
        )
        for s in await auth.list_sessions(principal.user_id)
    ]


@router.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={**_ERRORS, **error_responses(404)},
    summary="Revoke one of the current user's sessions",
)
async def revoke_session(
    session_id: uuid.UUID, principal: CurrentPrincipal, auth: AuthServiceDep, meta: RequestMetaDep
) -> None:
    if not await auth.revoke_session(principal, session_id, meta):
        raise NotFoundError("Session not found.")


@router.post(
    "/password-reset/request",
    status_code=status.HTTP_202_ACCEPTED,
    responses=_ERRORS,
    summary="Request a password reset email",
)
async def request_password_reset(
    payload: PasswordResetRequest,
    auth: AuthServiceDep,
    limiter: RateLimiterDep,
    meta: RequestMetaDep,
    settings: SettingsDep,
) -> MessageResponse:
    limit = settings.rate_limit_password_reset_per_hour
    await limiter.enforce(
        "reset:ip", meta.ip_address or "unknown", limit=limit, window_seconds=_HOUR
    )
    await limiter.enforce("reset:account", payload.email.lower(), limit=limit, window_seconds=_HOUR)
    await auth.request_password_reset(payload.email, meta)
    return MessageResponse(
        message="If an account exists for this email, a reset link has been sent."
    )


@router.post(
    "/password-reset/confirm",
    status_code=status.HTTP_204_NO_CONTENT,
    responses=_ERRORS,
    summary="Set a new password using a reset token",
)
async def confirm_password_reset(
    payload: PasswordResetConfirm,
    auth: AuthServiceDep,
    limiter: RateLimiterDep,
    meta: RequestMetaDep,
    settings: SettingsDep,
) -> None:
    await limiter.enforce(
        "reset-confirm:ip",
        meta.ip_address or "unknown",
        limit=settings.rate_limit_password_reset_per_hour,
        window_seconds=_HOUR,
    )
    await auth.confirm_password_reset(payload.token, payload.new_password, meta)


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    responses={**_ERRORS, **error_responses(409)},
    summary="Self-registration (disabled unless SENTINELX_ALLOW_SELF_REGISTRATION=true)",
)
async def register(
    payload: RegisterRequest,
    auth: AuthServiceDep,
    limiter: RateLimiterDep,
    meta: RequestMetaDep,
    settings: SettingsDep,
) -> UserRead:
    await limiter.enforce(
        "register:ip",
        meta.ip_address or "unknown",
        limit=settings.rate_limit_register_per_hour,
        window_seconds=_HOUR,
    )
    user = await auth.register(
        email=payload.email, full_name=payload.full_name, password=payload.password, meta=meta
    )
    return UserRead.from_model(user, now=utcnow())
