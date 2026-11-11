"""Project tenancy isolation, membership and the audit trail."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.permissions import RoleName
from tests.integration.conftest import ApiStack

pytestmark = pytest.mark.integration

PROJECTS = "/api/v1/projects"


async def _project(stack: ApiStack, headers: dict[str, str], name: str) -> dict[str, object]:
    response = await stack.client.post(PROJECTS, headers=headers, json={"name": name})
    assert response.status_code == 201, response.text
    body: dict[str, object] = response.json()
    return body


async def test_create_project_generates_unique_slug_and_membership(stack: ApiStack) -> None:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)

    first = await _project(stack, admin, "Acme Corp — External")
    second = await _project(stack, admin, "Acme Corp — External")

    assert first["slug"] == "acme-corp-external"
    assert second["slug"] != first["slug"]
    assert str(second["slug"]).startswith("acme-corp-external-")
    assert first["member_count"] == 1


async def test_non_members_cannot_see_projects(stack: ApiStack) -> None:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)
    viewer_user = await stack.create_user("viewer@example.com")
    viewer = await stack.login("viewer@example.com")
    visible = await _project(stack, admin, "Visible")
    hidden = await _project(stack, admin, "Hidden")
    await stack.client.post(
        f"{PROJECTS}/{visible['id']}/members", headers=admin, json={"user_id": str(viewer_user.id)}
    )

    listing = (await stack.client.get(PROJECTS, headers=viewer)).json()
    assert [p["name"] for p in listing["items"]] == ["Visible"]

    # Foreign projects are reported as missing (404), not forbidden (403).
    for path in (f"{PROJECTS}/{hidden['id']}", f"{PROJECTS}/{hidden['id']}/members"):
        response = await stack.client.get(path, headers=viewer)
        assert response.status_code == 404
    assert (
        await stack.client.get(f"{PROJECTS}/{visible['id']}", headers=viewer)
    ).status_code == 200


async def test_membership_management(stack: ApiStack) -> None:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)
    analyst = await stack.create_user("analyst@example.com", role=RoleName.SECURITY_ANALYST)
    inactive = await stack.create_user("inactive@example.com", is_active=False)
    project = await _project(stack, admin, "Members")
    members_url = f"{PROJECTS}/{project['id']}/members"

    added = await stack.client.post(members_url, headers=admin, json={"user_id": str(analyst.id)})
    assert added.status_code == 201
    assert added.json()["role"] == "security_analyst"

    duplicate = await stack.client.post(
        members_url, headers=admin, json={"user_id": str(analyst.id)}
    )
    assert duplicate.status_code == 409
    rejected = await stack.client.post(
        members_url, headers=admin, json={"user_id": str(inactive.id)}
    )
    assert rejected.status_code == 422

    members = (await stack.client.get(members_url, headers=admin)).json()
    assert {m["email"] for m in members} == {"admin@example.com", "analyst@example.com"}

    removed = await stack.client.delete(f"{members_url}/{analyst.id}", headers=admin)
    assert removed.status_code == 204
    again = await stack.client.delete(f"{members_url}/{analyst.id}", headers=admin)
    assert again.status_code == 404


async def test_members_cannot_manage_projects(stack: ApiStack) -> None:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)
    analyst_user = await stack.create_user("analyst@example.com", role=RoleName.SECURITY_ANALYST)
    analyst = await stack.login("analyst@example.com")
    project = await _project(stack, admin, "Locked")
    await stack.client.post(
        f"{PROJECTS}/{project['id']}/members", headers=admin, json={"user_id": str(analyst_user.id)}
    )

    patch = await stack.client.patch(
        f"{PROJECTS}/{project['id']}", headers=analyst, json={"name": "x"}
    )
    delete = await stack.client.delete(f"{PROJECTS}/{project['id']}", headers=analyst)

    assert patch.status_code == 403
    assert delete.status_code == 403


async def test_update_and_delete_project(stack: ApiStack) -> None:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)
    project = await _project(stack, admin, "Before")

    updated = await stack.client.patch(
        f"{PROJECTS}/{project['id']}",
        headers=admin,
        json={"name": "After", "description": "Scope: *.example.com"},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "After"
    assert updated.json()["slug"] == project["slug"]  # slugs are stable identifiers

    assert (
        await stack.client.delete(f"{PROJECTS}/{project['id']}", headers=admin)
    ).status_code == 204
    assert (await stack.client.get(f"{PROJECTS}/{project['id']}", headers=admin)).status_code == 404


async def test_audit_log_records_and_filters_actions(stack: ApiStack) -> None:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)
    await _project(stack, admin, "Audited")

    response = await stack.client.get(
        "/api/v1/audit-logs",
        headers={**admin, "X-Request-ID": "audit-test-0001"},
        params={"action": "project.created"},
    )

    assert response.status_code == 200
    page = response.json()
    assert page["total"] == 1
    entry = page["items"][0]
    assert entry["actor_email"] == "admin@example.com"
    assert entry["outcome"] == "success"
    assert entry["details"] == {"name": "Audited"}
    assert entry["ip_address"] == "127.0.0.1"

    actions = (await stack.client.get("/api/v1/audit-logs/actions", headers=admin)).json()
    assert {"auth.login", "project.created"} <= set(actions)

    failures = (
        await stack.client.get("/api/v1/audit-logs", headers=admin, params={"outcome": "failure"})
    ).json()
    assert failures["total"] == 0


async def test_audit_log_is_append_only(stack: ApiStack) -> None:
    await stack.user_headers("admin@example.com", RoleName.ADMIN)

    async with stack.app.state.session_factory() as session:
        for statement in ("UPDATE audit_logs SET action = 'tampered'", "DELETE FROM audit_logs"):
            with pytest.raises(DBAPIError, match="append-only"):
                await session.execute(text(statement))
            await session.rollback()
