"""Authentication, session lifecycle and credential flows against real PostgreSQL."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from sqlalchemy import select, update

from app.core.config import Settings
from app.core.permissions import Permission, RoleName
from app.models import AuditLog, PasswordResetToken, RefreshToken
from tests.integration.conftest import DEFAULT_PASSWORD, ApiStack, integration_settings

pytestmark = pytest.mark.integration

LOGIN = "/api/v1/auth/login"
REFRESH = "/api/v1/auth/refresh"
LOGOUT = "/api/v1/auth/logout"
ME = "/api/v1/auth/me"


def csrf_headers(stack: ApiStack) -> dict[str, str]:
    return {"X-CSRF-Token": stack.client.cookies.get("sentinelx_csrf") or ""}


async def audit_actions(stack: ApiStack) -> list[tuple[str, str]]:
    async with stack.app.state.session_factory() as session:
        rows = await session.execute(
            select(AuditLog.action, AuditLog.outcome).order_by(AuditLog.created_at)
        )
        return [(a, o) for a, o in rows.all()]


# ----------------------------------------------------------------------------- login


async def test_login_returns_token_cookies_and_permissions(stack: ApiStack) -> None:
    await stack.create_user("analyst@example.com", role=RoleName.SECURITY_ANALYST)

    response = await stack.client.post(
        LOGIN, json={"email": "Analyst@Example.com", "password": DEFAULT_PASSWORD}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["role"] == "security_analyst"
    assert Permission.SCANS_EXECUTE.value in body["user"]["permissions"]
    assert Permission.USERS_MANAGE.value not in body["user"]["permissions"]

    cookies = response.headers.get_list("set-cookie")
    refresh_cookie = next(c for c in cookies if c.startswith("sentinelx_refresh="))
    assert "HttpOnly" in refresh_cookie
    assert "SameSite=strict" in refresh_cookie
    assert "Path=/api/v1/auth" in refresh_cookie
    csrf_cookie = next(c for c in cookies if c.startswith("sentinelx_csrf="))
    assert "HttpOnly" not in csrf_cookie

    me = await stack.client.get(ME, headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json()["email"] == "analyst@example.com"
    assert ("auth.login", "success") in await audit_actions(stack)


@pytest.mark.parametrize(
    ("email", "password"),
    [("viewer@example.com", "wrong-password-123"), ("nobody@example.com", DEFAULT_PASSWORD)],
)
async def test_failed_login_is_generic_and_audited(
    stack: ApiStack, email: str, password: str
) -> None:
    await stack.create_user("viewer@example.com")

    response = await stack.client.post(LOGIN, json={"email": email, "password": password})

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Invalid email or password."
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert ("auth.login", "failure") in await audit_actions(stack)


async def test_account_locks_after_repeated_failures(stack: ApiStack) -> None:
    await stack.create_user("target@example.com")
    for _ in range(stack.settings.login_max_failures):
        bad = await stack.client.post(
            LOGIN, json={"email": "target@example.com", "password": "not-the-password"}
        )
        assert bad.status_code == 401

    # Even the correct password is refused while locked, with the same generic error.
    locked = await stack.client.post(
        LOGIN, json={"email": "target@example.com", "password": DEFAULT_PASSWORD}
    )

    assert locked.status_code == 401
    assert locked.json()["error"]["message"] == "Invalid email or password."
    assert ("auth.account_locked", "success") in await audit_actions(stack)


async def test_inactive_user_cannot_login(stack: ApiStack) -> None:
    await stack.create_user("gone@example.com", is_active=False)

    response = await stack.client.post(
        LOGIN, json={"email": "gone@example.com", "password": DEFAULT_PASSWORD}
    )

    assert response.status_code == 401


async def test_login_payload_is_validated(stack: ApiStack) -> None:
    response = await stack.client.post(
        LOGIN, json={"email": "not-an-email", "password": "x", "role": "admin"}
    )

    assert response.status_code == 422


# ----------------------------------------------------------------------------- access tokens


@pytest.mark.parametrize(
    "mutate",
    [
        "garbage",
        "alg_none",
        "wrong_key",
        "expired",
        "wrong_audience",
    ],
)
async def test_invalid_access_tokens_are_rejected(stack: ApiStack, mutate: str) -> None:
    user = await stack.create_user("v@example.com")
    now = datetime.now(UTC)
    claims = {
        "sub": str(user.id),
        "ver": 0,
        "typ": "access",
        "iss": "sentinelx",
        "aud": "sentinelx-api",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=5),
    }
    key = stack.settings.secret_key.get_secret_value()
    token = {
        "garbage": "not.a.jwt",
        "alg_none": jwt.encode(claims, key="", algorithm="none"),
        "wrong_key": jwt.encode(claims, "another-secret-key-of-sufficient-length!!", "HS256"),
        "expired": jwt.encode({**claims, "exp": now - timedelta(minutes=1)}, key, "HS256"),
        "wrong_audience": jwt.encode({**claims, "aud": "other"}, key, "HS256"),
    }[mutate]

    response = await stack.client.get(ME, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401


async def test_missing_token_is_401(stack: ApiStack) -> None:
    assert (await stack.client.get(ME)).status_code == 401


# ----------------------------------------------------------------------------- refresh & CSRF


async def test_refresh_rotates_tokens(stack: ApiStack) -> None:
    await stack.create_user("r@example.com")
    await stack.login("r@example.com")
    first = stack.client.cookies.get("sentinelx_refresh")

    response = await stack.client.post(REFRESH, headers=csrf_headers(stack))

    assert response.status_code == 200
    assert response.json()["access_token"]
    assert stack.client.cookies.get("sentinelx_refresh") != first


async def test_refresh_token_reuse_revokes_the_whole_session(stack: ApiStack) -> None:
    await stack.create_user("victim@example.com")
    await stack.login("victim@example.com")
    stolen = stack.client.cookies.get("sentinelx_refresh")
    stolen_csrf = stack.client.cookies.get("sentinelx_csrf")
    assert stolen
    assert stolen_csrf

    # Legitimate client rotates the token.
    assert (await stack.client.post(REFRESH, headers=csrf_headers(stack))).status_code == 200
    legit_refresh = stack.client.cookies.get("sentinelx_refresh")
    legit_csrf = stack.client.cookies.get("sentinelx_csrf")

    # Attacker replays the old token -> reuse detected.
    stack.client.cookies.clear()
    stack.client.cookies.set("sentinelx_refresh", stolen, path="/api/v1/auth")
    stack.client.cookies.set("sentinelx_csrf", stolen_csrf)
    replay = await stack.client.post(REFRESH, headers={"X-CSRF-Token": stolen_csrf})
    assert replay.status_code == 401

    # The legitimate client's newer token is now revoked as well.
    stack.client.cookies.clear()
    stack.client.cookies.set("sentinelx_refresh", legit_refresh or "", path="/api/v1/auth")
    stack.client.cookies.set("sentinelx_csrf", legit_csrf or "")
    after = await stack.client.post(REFRESH, headers={"X-CSRF-Token": legit_csrf or ""})
    assert after.status_code == 401
    assert ("auth.refresh_token_reuse", "failure") in await audit_actions(stack)


@pytest.mark.parametrize("header", [None, "tampered.value"])
async def test_refresh_requires_matching_csrf_token(stack: ApiStack, header: str | None) -> None:
    await stack.create_user("c@example.com")
    await stack.login("c@example.com")

    headers = {} if header is None else {"X-CSRF-Token": header}
    response = await stack.client.post(REFRESH, headers=headers)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "csrf_failed"


async def test_csrf_token_is_bound_to_its_session(stack: ApiStack) -> None:
    await stack.create_user("a@example.com")
    await stack.create_user("b@example.com")
    await stack.login("a@example.com")
    other_csrf = stack.client.cookies.get("sentinelx_csrf") or ""
    stack.client.cookies.clear()
    await stack.login("b@example.com")

    # Cookie and header match each other, but were issued for another session.
    stack.client.cookies.set("sentinelx_csrf", other_csrf)
    response = await stack.client.post(REFRESH, headers={"X-CSRF-Token": other_csrf})

    assert response.status_code == 403


async def test_refresh_without_cookie_is_401(stack: ApiStack) -> None:
    assert (await stack.client.post(REFRESH)).status_code == 401


async def test_expired_refresh_token_is_rejected(stack: ApiStack) -> None:
    await stack.create_user("e@example.com")
    await stack.login("e@example.com")
    async with stack.app.state.session_factory() as session:
        await session.execute(
            update(RefreshToken).values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await session.commit()

    assert (await stack.client.post(REFRESH, headers=csrf_headers(stack))).status_code == 401


async def test_logout_revokes_session_and_clears_cookies(stack: ApiStack) -> None:
    await stack.create_user("l@example.com")
    await stack.login("l@example.com")
    refresh = stack.client.cookies.get("sentinelx_refresh") or ""
    csrf = csrf_headers(stack)

    response = await stack.client.post(LOGOUT, headers=csrf)

    assert response.status_code == 204
    assert any('sentinelx_refresh=""' in c for c in response.headers.get_list("set-cookie"))
    # Replaying the revoked token with a still-valid CSRF pair must fail.
    stack.client.cookies.set("sentinelx_refresh", refresh, path="/api/v1/auth")
    stack.client.cookies.set("sentinelx_csrf", csrf["X-CSRF-Token"])
    assert (await stack.client.post(REFRESH, headers=csrf)).status_code == 401
    assert ("auth.logout", "success") in await audit_actions(stack)


async def test_logout_without_session_is_idempotent(stack: ApiStack) -> None:
    assert (await stack.client.post(LOGOUT)).status_code == 204


# ----------------------------------------------------------------------------- sessions


async def test_list_and_revoke_sessions(stack: ApiStack) -> None:
    await stack.create_user("s@example.com")
    headers = await stack.login("s@example.com")
    stack.client.cookies.clear()
    await stack.login("s@example.com")  # second session (current cookie jar)

    sessions = (await stack.client.get("/api/v1/auth/sessions", headers=headers)).json()
    assert len(sessions) == 2
    assert sum(s["current"] for s in sessions) == 1

    other = next(s for s in sessions if not s["current"])
    revoked = await stack.client.delete(f"/api/v1/auth/sessions/{other['id']}", headers=headers)
    assert revoked.status_code == 204
    remaining = (await stack.client.get("/api/v1/auth/sessions", headers=headers)).json()
    assert [s["id"] for s in remaining] != [other["id"]]
    assert len(remaining) == 1

    missing = await stack.client.delete(f"/api/v1/auth/sessions/{other['id']}", headers=headers)
    assert missing.status_code == 404


# ----------------------------------------------------------------------------- passwords


async def test_change_password_invalidates_existing_tokens(stack: ApiStack) -> None:
    await stack.create_user("p@example.com")
    headers = await stack.login("p@example.com")

    wrong = await stack.client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={"current_password": "nope-nope-nope", "new_password": "a-brand-new-passphrase"},
    )
    assert wrong.status_code == 422

    weak = await stack.client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={"current_password": DEFAULT_PASSWORD, "new_password": "short"},
    )
    assert weak.status_code == 422

    ok = await stack.client.post(
        "/api/v1/auth/change-password",
        headers=headers,
        json={"current_password": DEFAULT_PASSWORD, "new_password": "a-brand-new-passphrase"},
    )
    assert ok.status_code == 204

    # The previous access token is rejected immediately (token_version bump).
    assert (await stack.client.get(ME, headers=headers)).status_code == 401
    await stack.login("p@example.com", "a-brand-new-passphrase")


async def test_password_reset_flow(stack: ApiStack) -> None:
    await stack.create_user("forgot@example.com")
    old_headers = await stack.login("forgot@example.com")

    requested = await stack.client.post(
        "/api/v1/auth/password-reset/request", json={"email": "forgot@example.com"}
    )
    assert requested.status_code == 202
    assert len(stack.email.outbox) == 1
    match = re.search(r"/reset-password#token=([\w-]+)", stack.email.outbox[0].body)
    assert match
    token = match.group(1)

    confirm = await stack.client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "new_password": "reset-passphrase-2026"},
    )
    assert confirm.status_code == 204
    assert (await stack.client.get(ME, headers=old_headers)).status_code == 401
    await stack.login("forgot@example.com", "reset-passphrase-2026")

    reused = await stack.client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": token, "new_password": "another-passphrase-2026"},
    )
    assert reused.status_code == 422


async def test_password_reset_does_not_reveal_unknown_accounts(stack: ApiStack) -> None:
    response = await stack.client.post(
        "/api/v1/auth/password-reset/request", json={"email": "ghost@example.com"}
    )

    assert response.status_code == 202
    assert "If an account exists" in response.json()["message"]
    assert stack.email.outbox == []


async def test_expired_reset_token_is_rejected(stack: ApiStack) -> None:
    await stack.create_user("late@example.com")
    await stack.client.post(
        "/api/v1/auth/password-reset/request", json={"email": "late@example.com"}
    )
    match = re.search(r"#token=([\w-]+)", stack.email.outbox[0].body)
    assert match
    async with stack.app.state.session_factory() as session:
        await session.execute(
            update(PasswordResetToken).values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await session.commit()

    response = await stack.client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": match.group(1), "new_password": "reset-passphrase-2026"},
    )

    assert response.status_code == 422


# ----------------------------------------------------------------------------- registration


async def test_self_registration_disabled_by_default(stack: ApiStack) -> None:
    response = await stack.client.post(
        "/api/v1/auth/register",
        json={"email": "new@example.com", "full_name": "New", "password": DEFAULT_PASSWORD},
    )

    assert response.status_code == 403


class TestRegistrationEnabled:
    @pytest.fixture
    def stack_settings(self) -> Settings:
        return integration_settings(allow_self_registration=True)

    async def test_registration_creates_viewer(self, stack: ApiStack) -> None:
        payload = {"email": "New@Example.com", "full_name": "New", "password": DEFAULT_PASSWORD}

        created = await stack.client.post("/api/v1/auth/register", json=payload)
        duplicate = await stack.client.post("/api/v1/auth/register", json=payload)

        assert created.status_code == 201
        assert created.json()["role"] == "viewer"
        assert created.json()["email"] == "new@example.com"
        assert duplicate.status_code == 409


# ----------------------------------------------------------------------------- rate limiting


class TestLoginRateLimit:
    @pytest.fixture
    def stack_settings(self) -> Settings:
        return integration_settings(rate_limit_login_per_minute=3)

    async def test_login_is_rate_limited(self, stack: ApiStack) -> None:
        payload = {"email": "x@example.com", "password": "whatever-password"}
        statuses = [(await stack.client.post(LOGIN, json=payload)).status_code for _ in range(4)]

        assert statuses == [401, 401, 401, 429]
        limited = await stack.client.post(LOGIN, json=payload)
        assert int(limited.headers["Retry-After"]) > 0
        assert limited.json()["error"]["code"] == "rate_limited"
