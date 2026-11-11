"""Asset inventory, authorizations and scope checks through the API."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.core.config import Settings
from app.core.permissions import RoleName
from tests.integration.conftest import ApiStack, integration_settings

pytestmark = pytest.mark.integration

NOW = datetime.now(UTC)


async def _setup(
    stack: ApiStack, role: RoleName = RoleName.SECURITY_ANALYST
) -> tuple[dict[str, str], dict[str, str], str]:
    """Admin creates a project and adds a member with ``role``. Returns headers + project id."""
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)
    member = await stack.create_user(f"{role.value}@example.com", role=role)
    project = (
        await stack.client.post("/api/v1/projects", headers=admin, json={"name": "Acme"})
    ).json()
    await stack.client.post(
        f"/api/v1/projects/{project['id']}/members", headers=admin, json={"user_id": str(member.id)}
    )
    return admin, await stack.login(member.email), project["id"]


def _authorization(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "authorized_by": "Jane Owner",
        "organization": "Acme Corp",
        "reference": "SOW-2026-114",
        "valid_from": (NOW - timedelta(hours=1)).isoformat(),
        "valid_until": (NOW + timedelta(days=30)).isoformat(),
        "allow_active": True,
        "ip_ranges": ["93.184.215.0/24"],
    }
    body.update(overrides)
    return body


async def _asset(
    stack: ApiStack, headers: dict[str, str], project_id: str, **body: Any
) -> dict[str, Any]:
    response = await stack.client.post(
        f"/api/v1/projects/{project_id}/assets", headers=headers, json=body
    )
    assert response.status_code == 201, response.text
    data: dict[str, Any] = response.json()
    return data


# ----------------------------------------------------------------------------- inventory


async def test_register_list_and_filter_assets(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)

    created = await _asset(
        stack,
        analyst,
        project,
        type="domain",
        value="Example.COM.",
        tags=["Prod", "web"],
        criticality="high",
    )
    await _asset(stack, analyst, project, type="ip_address", value="93.184.215.14")

    assert created["value"] == "example.com"
    assert created["tags"] == ["prod", "web"]
    assert created["eligibility"] == {
        "passive": False,
        "active": False,
        "intrusive": False,
        "reasons": ["No authorization is valid right now."],
    }
    url = f"/api/v1/projects/{project}/assets"
    assert (await stack.client.get(url, headers=analyst)).json()["total"] == 2
    assert (await stack.client.get(url, headers=analyst, params={"type": "ip_address"})).json()[
        "total"
    ] == 1
    assert (await stack.client.get(url, headers=analyst, params={"tag": "prod"})).json()[
        "total"
    ] == 1
    assert (await stack.client.get(url, headers=analyst, params={"search": "example"})).json()[
        "total"
    ] == 1


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ({"type": "ip_address", "value": "10.0.0.5"}, "not publicly routable"),
        ({"type": "ip_address", "value": "169.254.169.254"}, "not publicly routable"),
        ({"type": "domain", "value": "db.internal"}, "Special-use"),
        ({"type": "domain", "value": "2130706433"}, "numeric"),
        ({"type": "web_application", "value": "http://127.0.0.1:8080/"}, "not publicly routable"),
        ({"type": "web_application", "value": "example.com"}, "http(s) URL"),
        ({"type": "service", "value": "https://example.com/"}, "host:port"),
    ],
)
async def test_unsafe_or_malformed_assets_are_rejected(
    stack: ApiStack, body: dict[str, str], fragment: str
) -> None:
    _, analyst, project = await _setup(stack)

    response = await stack.client.post(
        f"/api/v1/projects/{project}/assets", headers=analyst, json=body
    )

    assert response.status_code == 422
    assert fragment in response.json()["error"]["message"]


async def test_duplicates_and_immutable_fields(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project, type="domain", value="example.com")

    duplicate = await stack.client.post(
        f"/api/v1/projects/{project}/assets",
        headers=analyst,
        json={"type": "domain", "value": "EXAMPLE.com"},
    )
    change_value = await stack.client.patch(
        f"/api/v1/projects/{project}/assets/{asset['id']}",
        headers=analyst,
        json={"value": "evil.example"},
    )

    assert duplicate.status_code == 409
    assert change_value.status_code == 422  # extra field forbidden: value is immutable


async def test_viewers_can_read_but_not_write(stack: ApiStack) -> None:
    admin, viewer, project = await _setup(stack, RoleName.VIEWER)
    asset = await _asset(stack, admin, project, type="domain", value="example.com")

    assert (
        await stack.client.get(f"/api/v1/projects/{project}/assets", headers=viewer)
    ).status_code == 200
    write = await stack.client.post(
        f"/api/v1/projects/{project}/assets",
        headers=viewer,
        json={"type": "domain", "value": "x.example.com"},
    )
    authorize = await stack.client.post(
        f"/api/v1/projects/{project}/assets/{asset['id']}/authorizations",
        headers=viewer,
        json=_authorization(),
    )
    assert write.status_code == 403
    assert authorize.status_code == 403


async def test_assets_are_isolated_between_projects(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    other = (
        await stack.client.post("/api/v1/projects", headers=admin, json={"name": "Other"})
    ).json()
    foreign = await _asset(stack, admin, other["id"], type="domain", value="example.com")

    for method, path in (
        ("GET", f"/api/v1/projects/{other['id']}/assets"),
        ("GET", f"/api/v1/projects/{other['id']}/assets/{foreign['id']}"),
        # Correct asset id, but through a project the analyst can see:
        ("GET", f"/api/v1/projects/{project}/assets/{foreign['id']}"),
    ):
        assert (await stack.client.request(method, path, headers=analyst)).status_code == 404, path

    check = await stack.client.post(
        f"/api/v1/projects/{other['id']}/scope/check",
        headers=analyst,
        json={"target": "example.com"},
    )
    assert check.status_code == 404


# ----------------------------------------------------------------------------- authorizations


async def test_authorization_lifecycle_and_history(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project, type="domain", value="example.com")
    base = f"/api/v1/projects/{project}/assets/{asset['id']}"

    created = await stack.client.post(
        f"{base}/authorizations", headers=analyst, json=_authorization()
    )
    assert created.status_code == 201, created.text
    assert created.json()["status"] == "active"

    detail = (await stack.client.get(base, headers=analyst)).json()
    assert detail["active_authorizations"] == 1
    assert detail["eligibility"]["active"] is True
    assert detail["eligibility"]["intrusive"] is False

    auth_id = created.json()["id"]
    revoked = await stack.client.post(
        f"{base}/authorizations/{auth_id}/revoke",
        headers=analyst,
        json={"reason": "Engagement ended"},
    )
    again = await stack.client.post(
        f"{base}/authorizations/{auth_id}/revoke", headers=analyst, json={"reason": "Twice"}
    )
    assert revoked.json()["status"] == "revoked"
    assert again.status_code == 409

    history = (await stack.client.get(f"{base}/history", headers=analyst)).json()
    assert [h["action"] for h in history] == [
        "asset.authorization_revoked",
        "asset.authorization_added",
        "asset.created",
    ]


@pytest.mark.parametrize(
    ("overrides", "fragment"),
    [
        ({"valid_until": (NOW - timedelta(hours=2)).isoformat()}, "end after it starts"),
        (
            {
                "valid_from": (NOW - timedelta(days=5)).isoformat(),
                "valid_until": (NOW - timedelta(days=1)).isoformat(),
            },
            "already ended",
        ),
        ({"valid_until": (NOW + timedelta(days=400)).isoformat()}, "at most 366 days"),
        ({"ip_ranges": ["0.0.0.0/0"]}, "too broad"),
        ({"ip_ranges": ["93.0.0.0/8"]}, "too broad"),
        ({"ip_ranges": ["10.0.0.0/16"]}, "not publicly routable"),
        ({"ip_ranges": ["93.184.215.1/24"]}, "not a valid network"),
        ({"allow_active": False, "allow_intrusive": True}, "administrators"),
    ],
)
async def test_authorization_validation(
    stack: ApiStack, overrides: dict[str, Any], fragment: str
) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project, type="ip_address", value="93.184.215.14")

    response = await stack.client.post(
        f"/api/v1/projects/{project}/assets/{asset['id']}/authorizations",
        headers=analyst,
        json=_authorization(**overrides),
    )

    assert response.status_code in (403, 422)
    assert fragment in response.json()["error"]["message"]


async def test_naive_datetimes_are_rejected(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project, type="domain", value="example.com")

    response = await stack.client.post(
        f"/api/v1/projects/{project}/assets/{asset['id']}/authorizations",
        headers=analyst,
        json=_authorization(valid_from="2026-11-11T00:00:00", valid_until="2026-12-01T00:00:00"),
    )

    assert response.status_code == 422


async def test_only_admins_may_authorize_intrusive_testing(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project, type="domain", value="example.com")
    url = f"/api/v1/projects/{project}/assets/{asset['id']}/authorizations"

    denied = await stack.client.post(
        url, headers=analyst, json=_authorization(allow_intrusive=True)
    )
    allowed = await stack.client.post(url, headers=admin, json=_authorization(allow_intrusive=True))

    assert denied.status_code == 403
    assert allowed.status_code == 201
    assert allowed.json()["allow_intrusive"] is True


async def test_subdomain_coverage_only_for_domains(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    ip_asset = await _asset(stack, analyst, project, type="ip_address", value="93.184.215.14")

    response = await stack.client.post(
        f"/api/v1/projects/{project}/assets/{ip_asset['id']}/authorizations",
        headers=analyst,
        json=_authorization(include_subdomains=True),
    )

    assert response.status_code == 422


async def test_archived_assets_lose_eligibility(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project, type="domain", value="example.com")
    base = f"/api/v1/projects/{project}/assets/{asset['id']}"
    await stack.client.post(f"{base}/authorizations", headers=analyst, json=_authorization())

    archived = await stack.client.patch(base, headers=analyst, json={"status": "archived"})
    new_auth = await stack.client.post(
        f"{base}/authorizations", headers=analyst, json=_authorization()
    )

    assert archived.json()["eligibility"]["active"] is False
    assert new_auth.status_code == 422
    history = (await stack.client.get(f"{base}/history", headers=analyst)).json()
    assert history[0]["action"] == "asset.archived"


async def test_database_enforces_authorization_invariants(stack: ApiStack) -> None:
    async with stack.app.state.session_factory() as session:
        with pytest.raises(IntegrityError, match="intrusive_requires_active"):
            await session.execute(
                text(
                    "INSERT INTO asset_authorizations (id, asset_id, project_id, "
                    "authorized_by, organization, reference, valid_from, valid_until, "
                    "allow_active, allow_intrusive) VALUES (gen_random_uuid(), "
                    "gen_random_uuid(), gen_random_uuid(), 'a', 'b', 'c', now(), "
                    "now() + interval '1 day', false, true)"
                )
            )


# ----------------------------------------------------------------------------- scope checks


async def _authorized_domain(
    stack: ApiStack, value: str = "example.com", **auth: Any
) -> tuple[dict[str, str], str]:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project, type="domain", value=value)
    response = await stack.client.post(
        f"/api/v1/projects/{project}/assets/{asset['id']}/authorizations",
        headers=analyst,
        json=_authorization(**auth),
    )
    assert response.status_code == 201, response.text
    return analyst, project


async def test_scope_check_explains_allowed_target(stack: ApiStack) -> None:
    analyst, project = await _authorized_domain(stack)

    decision = (
        await stack.client.post(
            f"/api/v1/projects/{project}/scope/check",
            headers=analyst,
            json={"target": "https://example.com/login", "technique": "active"},
        )
    ).json()

    assert decision["allowed"] is True
    assert decision["addresses"] == [{"address": "93.184.215.14", "allowed": True, "reason": None}]
    assert decision["reasons"][0]["code"] == "in_scope"


@pytest.mark.parametrize(
    ("domain", "target", "auth", "code"),
    [
        ("example.com", "www.example.com", {}, "no_matching_asset"),
        ("cdn.example.com", "cdn.example.com", {"ip_ranges": []}, "address_not_authorized"),
        ("rebind.example.com", "rebind.example.com", {}, "loopback_address"),
        ("example.com", "example.com", {"allow_active": False}, "technique_not_authorized"),
        ("example.com", "http://user:pw@example.com/", {}, "credentials_in_url"),
        ("example.com", "169.254.169.254", {}, "metadata_endpoint"),
        ("example.com", "http://[::ffff:127.0.0.1]/", {}, "embedded_loopback_address"),
    ],
)
async def test_scope_check_denials(
    stack: ApiStack, domain: str, target: str, auth: dict[str, Any], code: str
) -> None:
    analyst, project = await _authorized_domain(stack, domain, **auth)

    decision = (
        await stack.client.post(
            f"/api/v1/projects/{project}/scope/check", headers=analyst, json={"target": target}
        )
    ).json()

    assert decision["allowed"] is False
    assert code in {r["code"] for r in decision["reasons"]}


async def test_scope_check_is_rate_limited(stack: ApiStack) -> None:
    analyst, project = await _authorized_domain(stack)
    url = f"/api/v1/projects/{project}/scope/check"

    statuses = [
        (await stack.client.post(url, headers=analyst, json={"target": "example.com"})).status_code
        for _ in range(stack.settings.rate_limit_scope_check_per_minute + 1)
    ]

    assert statuses[-1] == 429
    assert set(statuses[:-1]) == {200}


class TestLabConfiguration:
    @pytest.fixture
    def stack_settings(self) -> Settings:
        return integration_settings(
            scope_lab_networks=["10.20.0.0/16"],
            scope_lab_domains=["lab.example.com"],
            rate_limit_scope_check_per_minute=1000,
        )

    async def test_lab_targets_can_be_registered_and_tested(self, stack: ApiStack) -> None:
        analyst, project = await _authorized_domain(
            stack, "juice.lab.example.com", ip_ranges=["10.20.0.0/16"]
        )

        decision = (
            await stack.client.post(
                f"/api/v1/projects/{project}/scope/check",
                headers=analyst,
                json={"target": "juice.lab.example.com"},
            )
        ).json()

        assert decision["allowed"] is True
