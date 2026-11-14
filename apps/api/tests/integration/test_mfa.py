"""TOTP multi-factor authentication: enrolment, login, replay, recovery, lockout, reset."""

from __future__ import annotations

import time

import pytest
from sqlalchemy import select

from app.core.permissions import RoleName
from app.core.security import totp
from app.models import AuditLog, UserMfa
from tests.integration.conftest import DEFAULT_PASSWORD, ApiStack

pytestmark = pytest.mark.integration

API = "/api/v1"
EMAIL = "mfa@example.com"


async def _enable(stack: ApiStack, headers: dict[str, str]) -> tuple[str, list[str]]:
    started = await stack.client.post(
        f"{API}/auth/mfa/enroll", headers=headers, json={"password": DEFAULT_PASSWORD}
    )
    assert started.status_code == 200, started.text
    secret = started.json()["secret"]
    assert started.json()["otpauth_uri"].startswith("otpauth://totp/")
    confirmed = await stack.client.post(
        f"{API}/auth/mfa/confirm",
        headers=headers,
        json={"code": totp.generate(secret, time.time())},
    )
    assert confirmed.status_code == 200, confirmed.text
    return secret, confirmed.json()["recovery_codes"]


async def _login(stack: ApiStack, email: str = EMAIL) -> dict:  # type: ignore[type-arg]
    response = await stack.client.post(
        f"{API}/auth/login", json={"email": email, "password": DEFAULT_PASSWORD}
    )
    assert response.status_code == 200, response.text
    data: dict = response.json()  # type: ignore[type-arg]
    return data


async def test_enrolment_requires_password_and_a_valid_code(stack: ApiStack) -> None:
    headers = await stack.user_headers(EMAIL, RoleName.SECURITY_ANALYST)
    bad = await stack.client.post(
        f"{API}/auth/mfa/enroll", headers=headers, json={"password": "wrong-password-123"}
    )
    assert bad.status_code == 422
    status = (await stack.client.get(f"{API}/auth/mfa", headers=headers)).json()
    assert status == {"enabled": False, "pending_enrollment": False, "recovery_codes_remaining": 0}

    started = (
        await stack.client.post(
            f"{API}/auth/mfa/enroll", headers=headers, json={"password": DEFAULT_PASSWORD}
        )
    ).json()
    wrong = await stack.client.post(
        f"{API}/auth/mfa/confirm", headers=headers, json={"code": "000000"}
    )
    assert wrong.status_code == 422
    # Still pending: login does not ask for MFA until confirmed.
    assert "access_token" in await _login(stack)

    codes = (
        await stack.client.post(
            f"{API}/auth/mfa/confirm",
            headers=headers,
            json={"code": totp.generate(started["secret"], time.time())},
        )
    ).json()["recovery_codes"]
    assert len(codes) == totp.RECOVERY_CODE_COUNT
    assert len(set(codes)) == len(codes)
    status = (await stack.client.get(f"{API}/auth/mfa", headers=headers)).json()
    assert status["enabled"] is True
    assert status["recovery_codes_remaining"] == totp.RECOVERY_CODE_COUNT
    again = await stack.client.post(
        f"{API}/auth/mfa/enroll", headers=headers, json={"password": DEFAULT_PASSWORD}
    )
    assert again.status_code == 409


async def test_secret_and_recovery_codes_are_not_stored_in_clear(stack: ApiStack) -> None:
    headers = await stack.user_headers(EMAIL, RoleName.SECURITY_ANALYST)
    secret, codes = await _enable(stack, headers)
    async with stack.app.state.session_factory() as session:
        record = (await session.execute(select(UserMfa))).scalar_one()
    assert secret not in record.secret_encrypted
    stored = " ".join(record.recovery_code_hashes)
    assert all(code.replace("-", "") not in stored for code in codes)


async def test_login_needs_second_factor_and_codes_cannot_be_replayed(stack: ApiStack) -> None:
    headers = await stack.user_headers(EMAIL, RoleName.SECURITY_ANALYST)
    secret, _ = await _enable(stack, headers)
    stack.client.cookies.clear()  # drop the session from the helper login

    challenge = await _login(stack)
    assert challenge["mfa_required"] is True
    assert "access_token" not in challenge
    assert "sentinelx_refresh" not in stack.client.cookies
    # The challenge is not an access token.
    probe = await stack.client.get(
        f"{API}/auth/me", headers={"Authorization": f"Bearer {challenge['challenge_token']}"}
    )
    assert probe.status_code == 401

    wrong = await stack.client.post(
        f"{API}/auth/mfa/verify",
        json={"challenge_token": challenge["challenge_token"], "code": "123456"},
    )
    assert wrong.status_code == 401

    # The code used while enabling MFA is burned for its time step: no replay.
    burned = await stack.client.post(
        f"{API}/auth/mfa/verify",
        json={
            "challenge_token": challenge["challenge_token"],
            "code": totp.generate(secret, time.time()),
        },
    )
    assert burned.status_code == 401

    # The next time step is accepted (clock-drift window) and starts a session.
    code = totp.generate(secret, time.time() + totp.PERIOD)
    ok = await stack.client.post(
        f"{API}/auth/mfa/verify",
        json={"challenge_token": challenge["challenge_token"], "code": code},
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["user"]["email"] == EMAIL
    assert "sentinelx_refresh" in stack.client.cookies

    second = await _login(stack)
    replay = await stack.client.post(
        f"{API}/auth/mfa/verify",
        json={"challenge_token": second["challenge_token"], "code": code},
    )
    assert replay.status_code == 401


async def test_recovery_codes_work_once(stack: ApiStack) -> None:
    headers = await stack.user_headers(EMAIL, RoleName.SECURITY_ANALYST)
    _, codes = await _enable(stack, headers)
    challenge = await _login(stack)
    ok = await stack.client.post(
        f"{API}/auth/mfa/verify",
        json={"challenge_token": challenge["challenge_token"], "code": codes[0].upper()},
    )
    assert ok.status_code == 200, ok.text
    access = {"Authorization": f"Bearer {ok.json()['access_token']}"}
    status = (await stack.client.get(f"{API}/auth/mfa", headers=access)).json()
    assert status["recovery_codes_remaining"] == totp.RECOVERY_CODE_COUNT - 1

    again = await _login(stack)
    reuse = await stack.client.post(
        f"{API}/auth/mfa/verify",
        json={"challenge_token": again["challenge_token"], "code": codes[0]},
    )
    assert reuse.status_code == 401


async def test_wrong_codes_lock_the_account(stack: ApiStack) -> None:
    headers = await stack.user_headers(EMAIL, RoleName.SECURITY_ANALYST)
    secret, _ = await _enable(stack, headers)
    challenge = await _login(stack)
    for _ in range(stack.settings.login_max_failures):
        bad = await stack.client.post(
            f"{API}/auth/mfa/verify",
            json={"challenge_token": challenge["challenge_token"], "code": "654321"},
        )
        assert bad.status_code == 401
    locked = await stack.client.post(
        f"{API}/auth/mfa/verify",
        json={
            "challenge_token": challenge["challenge_token"],
            "code": totp.generate(secret, time.time() + totp.PERIOD),
        },
    )
    assert locked.status_code == 401  # even a valid code is refused while locked
    async with stack.app.state.session_factory() as session:
        actions = {a for (a,) in (await session.execute(select(AuditLog.action))).all()}
    assert "auth.account_locked" in actions


async def test_disable_needs_password_and_code(stack: ApiStack) -> None:
    headers = await stack.user_headers(EMAIL, RoleName.SECURITY_ANALYST)
    _secret, codes = await _enable(stack, headers)
    url = f"{API}/auth/mfa/disable"
    bad_pw = await stack.client.post(
        url, headers=headers, json={"password": "wrong-password-123", "code": codes[0]}
    )
    assert bad_pw.status_code == 422
    bad_code = await stack.client.post(
        url, headers=headers, json={"password": DEFAULT_PASSWORD, "code": "000000"}
    )
    assert bad_code.status_code == 422
    ok = await stack.client.post(
        url, headers=headers, json={"password": DEFAULT_PASSWORD, "code": codes[1]}
    )
    assert ok.status_code == 204
    assert (await stack.client.get(f"{API}/auth/mfa", headers=headers)).json()["enabled"] is False
    assert "access_token" in await _login(stack)


async def test_admin_reset_removes_mfa_and_signs_the_user_out(stack: ApiStack) -> None:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)
    user = await stack.create_user(EMAIL, role=RoleName.SECURITY_ANALYST)
    headers = await stack.login(EMAIL)
    await _enable(stack, headers)
    analyst = await stack.user_headers("other@example.com", RoleName.SECURITY_ANALYST)

    forbidden = await stack.client.post(f"{API}/users/{user.id}/mfa/reset", headers=analyst)
    assert forbidden.status_code == 403
    reset = await stack.client.post(f"{API}/users/{user.id}/mfa/reset", headers=admin)
    assert reset.status_code == 204
    assert (await stack.client.get(f"{API}/auth/me", headers=headers)).status_code == 401
    assert "access_token" in await _login(stack)
    async with stack.app.state.session_factory() as session:
        actions = {a for (a,) in (await session.execute(select(AuditLog.action))).all()}
    assert {"user.mfa_reset", "auth.mfa_enabled"} <= actions
