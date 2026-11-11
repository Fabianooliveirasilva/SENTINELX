"""Role-based access control and user administration."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.core.permissions import ROLE_PERMISSIONS, Permission, RoleName
from app.models import Role
from tests.integration.conftest import DEFAULT_PASSWORD, ApiStack

pytestmark = pytest.mark.integration

USERS = "/api/v1/users"


async def test_database_rbac_seed_matches_code_catalog(stack: ApiStack) -> None:
    async with stack.app.state.session_factory() as session:
        roles = (await session.execute(select(Role))).scalars().all()
        seeded = {RoleName(r.name): {Permission(p.code) for p in r.permissions} for r in roles}

    assert seeded == {role: set(perms) for role, perms in ROLE_PERMISSIONS.items()}


@pytest.mark.parametrize(
    ("role", "method", "path", "expected"),
    [
        (RoleName.VIEWER, "GET", USERS, 403),
        (RoleName.VIEWER, "GET", "/api/v1/roles", 403),
        (RoleName.VIEWER, "GET", "/api/v1/audit-logs", 403),
        (RoleName.VIEWER, "POST", "/api/v1/projects", 403),
        (RoleName.SECURITY_ANALYST, "GET", USERS, 403),
        (RoleName.SECURITY_ANALYST, "POST", USERS, 403),
        (RoleName.SECURITY_ANALYST, "GET", "/api/v1/audit-logs", 403),
        (RoleName.SECURITY_ANALYST, "POST", "/api/v1/projects", 403),
        (RoleName.ADMIN, "GET", USERS, 200),
        (RoleName.ADMIN, "GET", "/api/v1/roles", 200),
        (RoleName.ADMIN, "GET", "/api/v1/audit-logs", 200),
    ],
)
async def test_permission_matrix(
    stack: ApiStack, role: RoleName, method: str, path: str, expected: int
) -> None:
    headers = await stack.user_headers(f"{role.value}@example.com", role)
    body = {"name": "x"} if path.endswith("projects") else None
    if method == "POST" and path == USERS:
        body = {"email": "n@example.com", "full_name": "N", "password": DEFAULT_PASSWORD}

    response = await stack.client.request(method, path, headers=headers, json=body)

    assert response.status_code == expected, response.text
    if expected == 403:
        assert response.json()["error"]["code"] == "permission_denied"


async def test_protected_endpoints_require_authentication(stack: ApiStack) -> None:
    for path in (USERS, "/api/v1/roles", "/api/v1/projects", "/api/v1/audit-logs"):
        assert (await stack.client.get(path)).status_code == 401


async def test_admin_creates_lists_and_filters_users(stack: ApiStack) -> None:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)

    created = await stack.client.post(
        USERS,
        headers=admin,
        json={
            "email": "Analyst@Example.com",
            "full_name": "Ana Lyst",
            "password": DEFAULT_PASSWORD,
            "role": "security_analyst",
        },
    )
    assert created.status_code == 201
    assert created.json()["email"] == "analyst@example.com"

    page = (
        await stack.client.get(USERS, headers=admin, params={"role": "security_analyst"})
    ).json()
    assert page["total"] == 1
    assert page["items"][0]["full_name"] == "Ana Lyst"

    search = (await stack.client.get(USERS, headers=admin, params={"search": "ana%"})).json()
    assert search["total"] == 0  # wildcard characters are escaped, not interpreted

    paged = (await stack.client.get(USERS, headers=admin, params={"page_size": 1})).json()
    assert paged["total"] == 2
    assert len(paged["items"]) == 1


@pytest.mark.parametrize(
    ("payload", "status"),
    [
        ({"email": "admin@example.com", "full_name": "Dup", "password": DEFAULT_PASSWORD}, 409),
        ({"email": "weak@example.com", "full_name": "Weak", "password": "short"}, 422),
        (
            {
                "email": "x@example.com",
                "full_name": "X",
                "password": DEFAULT_PASSWORD,
                "is_superuser": True,
            },
            422,
        ),
        (
            {
                "email": "x@example.com",
                "full_name": "X",
                "password": DEFAULT_PASSWORD,
                "role": "root",
            },
            422,
        ),
    ],
)
async def test_user_creation_validation(
    stack: ApiStack, payload: dict[str, object], status: int
) -> None:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)

    response = await stack.client.post(USERS, headers=admin, json=payload)

    assert response.status_code == status


async def test_admin_cannot_demote_or_deactivate_self(stack: ApiStack) -> None:
    admin_user = await stack.create_user("admin@example.com", role=RoleName.ADMIN)
    headers = await stack.login("admin@example.com")

    for change in ({"role": "viewer"}, {"is_active": False}):
        response = await stack.client.patch(
            f"{USERS}/{admin_user.id}", headers=headers, json=change
        )
        assert response.status_code == 422


async def test_last_active_admin_is_protected(stack: ApiStack) -> None:
    first = await stack.create_user("first@example.com", role=RoleName.ADMIN)
    second = await stack.create_user("second@example.com", role=RoleName.ADMIN)
    headers = await stack.login("first@example.com")

    # Demoting the other admin is fine while one admin remains...
    ok = await stack.client.patch(f"{USERS}/{second.id}", headers=headers, json={"role": "viewer"})
    assert ok.status_code == 200
    assert ok.json()["role"] == "viewer"

    # ...and the remaining admin cannot remove themselves.
    blocked = await stack.client.patch(
        f"{USERS}/{first.id}", headers=headers, json={"role": "viewer"}
    )
    assert blocked.status_code == 422


async def test_deactivation_revokes_access_immediately(stack: ApiStack) -> None:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)
    target = await stack.create_user("target@example.com")
    target_headers = await stack.login("target@example.com")
    assert (await stack.client.get("/api/v1/auth/me", headers=target_headers)).status_code == 200

    response = await stack.client.patch(
        f"{USERS}/{target.id}", headers=admin, json={"is_active": False}
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is False
    assert (await stack.client.get("/api/v1/auth/me", headers=target_headers)).status_code == 401


async def test_role_change_applies_to_existing_tokens(stack: ApiStack) -> None:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)
    target = await stack.create_user("promote@example.com")
    target_headers = await stack.login("promote@example.com")
    assert (await stack.client.get(USERS, headers=target_headers)).status_code == 403

    await stack.client.patch(f"{USERS}/{target.id}", headers=admin, json={"role": "admin"})

    # Permissions are resolved from the database on every request, not the token.
    assert (await stack.client.get(USERS, headers=target_headers)).status_code == 200


async def test_admin_can_force_logout(stack: ApiStack) -> None:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)
    target = await stack.create_user("t@example.com")
    target_headers = await stack.login("t@example.com")

    response = await stack.client.post(f"{USERS}/{target.id}/revoke-sessions", headers=admin)

    assert response.status_code == 204
    assert (await stack.client.get("/api/v1/auth/me", headers=target_headers)).status_code == 401


async def test_unknown_user_is_404(stack: ApiStack) -> None:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)
    missing = "00000000-0000-0000-0000-000000000000"

    assert (await stack.client.get(f"{USERS}/{missing}", headers=admin)).status_code == 404
    assert (
        await stack.client.patch(f"{USERS}/{missing}", headers=admin, json={"full_name": "x"})
    ).status_code == 404


async def test_roles_endpoint_lists_catalog(stack: ApiStack) -> None:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)

    roles = (await stack.client.get("/api/v1/roles", headers=admin)).json()

    assert {r["name"] for r in roles} == {"admin", "security_analyst", "viewer"}
    viewer = next(r for r in roles if r["name"] == "viewer")
    assert "users:read" not in viewer["permissions"]
