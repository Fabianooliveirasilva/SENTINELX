from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.permissions import ROLE_PERMISSIONS, Permission, RoleName
from app.core.security.passwords import PasswordService, validate_password_strength
from app.core.security.tokens import (
    AccessTokenService,
    InvalidTokenError,
    generate_opaque_token,
    hash_opaque_token,
    tokens_match,
)
from app.services.auth import CsrfSigner
from app.services.projects import slugify
from tests.conftest import build_settings

FAST = {"argon2_time_cost": 1, "argon2_memory_cost_kib": 1024}


# ----------------------------------------------------------------------------- passwords


async def test_password_hash_roundtrip_uses_argon2id() -> None:
    service = PasswordService(build_settings(**FAST))

    hashed = await service.hash("correct-horse-battery")

    assert hashed.startswith("$argon2id$")
    assert (await service.verify(hashed, "correct-horse-battery")).valid
    assert not (await service.verify(hashed, "wrong-password-value")).valid
    assert not (await service.verify("not-a-hash", "whatever")).valid


async def test_unknown_account_verification_is_always_false() -> None:
    service = PasswordService(build_settings(**FAST))

    assert not (await service.verify(None, "sentinelx-timing-equalizer")).valid


async def test_rehash_is_flagged_when_parameters_change() -> None:
    old = await PasswordService(build_settings(**FAST)).hash("a-long-enough-password")
    stronger = PasswordService(build_settings(argon2_time_cost=2, argon2_memory_cost_kib=2048))

    result = await stronger.verify(old, "a-long-enough-password")

    assert result.valid
    assert result.needs_rehash


@pytest.mark.parametrize(
    ("password", "message"),
    [
        ("short", "at least"),
        ("x" * 129, "at most"),
        (" " * 20, "blank"),
        ("alice@example.com", "email"),
        ("ALICE-example-long", None),
    ],
)
def test_password_policy(password: str, message: str | None) -> None:
    if message is None:
        assert validate_password_strength(password, email="alice@example.com") == password
        return
    with pytest.raises(ValueError, match=message):
        validate_password_strength(password, email="alice@example.com")


# ----------------------------------------------------------------------------- tokens


def _service() -> AccessTokenService:
    return AccessTokenService(build_settings())


def test_access_token_roundtrip() -> None:
    service = _service()
    user_id = uuid.uuid4()

    issued = service.issue(user_id, token_version=3)
    claims = service.decode(issued.token)

    assert claims.user_id == user_id
    assert claims.token_version == 3
    assert issued.expires_in == 600


@pytest.mark.parametrize("override", [{"typ": "refresh"}, {"ver": True}, {"ver": "1"}])
def test_access_token_rejects_wrong_claim_types(override: dict[str, object]) -> None:
    settings = build_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": str(uuid.uuid4()),
        "ver": 0,
        "typ": "access",
        "iss": "sentinelx",
        "aud": "sentinelx-api",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=1),
        **override,
    }
    token = jwt.encode(payload, settings.secret_key.get_secret_value(), algorithm="HS256")

    with pytest.raises(InvalidTokenError):
        AccessTokenService(settings).decode(token)


def test_access_token_rejects_missing_claims() -> None:
    settings = build_settings()
    token = jwt.encode({"sub": "x"}, settings.secret_key.get_secret_value(), algorithm="HS256")

    with pytest.raises(InvalidTokenError):
        AccessTokenService(settings).decode(token)


def test_opaque_tokens_are_random_and_hashed() -> None:
    first, second = generate_opaque_token(), generate_opaque_token()

    assert first != second
    assert len(first) >= 43
    assert hash_opaque_token(first) != first
    assert len(hash_opaque_token(first)) == 64
    assert tokens_match("abc", "abc")
    assert not tokens_match("abc", "abd")


def test_csrf_tokens_are_bound_to_session_family() -> None:
    signer = CsrfSigner("secret-key-for-tests-0000000000000000")
    family = uuid.uuid4()
    token = signer.issue(family)

    assert signer.verify(token, family)
    assert not signer.verify(token, uuid.uuid4())
    assert not signer.verify("no-signature", family)
    assert not signer.verify(token + "x", family)
    assert not CsrfSigner("another-secret-key-000000000000000000").verify(token, family)


# ----------------------------------------------------------------------------- RBAC catalog


def test_role_hierarchy_is_least_privilege() -> None:
    viewer = ROLE_PERMISSIONS[RoleName.VIEWER]
    analyst = ROLE_PERMISSIONS[RoleName.SECURITY_ANALYST]
    admin = ROLE_PERMISSIONS[RoleName.ADMIN]

    assert viewer < analyst < admin
    assert admin == frozenset(Permission)
    assert all(p.value.endswith(":read") for p in viewer)
    assert not analyst & {
        Permission.USERS_MANAGE,
        Permission.AUDIT_READ,
        Permission.SETTINGS_MANAGE,
    }


# ----------------------------------------------------------------------------- slugs


@pytest.mark.parametrize(
    ("name", "slug"),
    [
        ("Acme Corp", "acme-corp"),
        ("  Ünïcödé — Name!! ", "unicode-name"),
        ("***", "project"),
        ("a" * 200, "a" * 120),
    ],
)
def test_slugify(name: str, slug: str) -> None:
    assert slugify(name) == slug
