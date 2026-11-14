"""Dashboard: figures come from stored data and respect project access."""

from __future__ import annotations

import uuid

import pytest

from app.core.permissions import RoleName
from tests.integration.conftest import ApiStack
from tests.integration.test_findings import _scan
from tests.integration.test_scans import _asset, _request, _setup

pytestmark = pytest.mark.integration


async def _dashboard(stack: ApiStack, headers: dict[str, str], **params: str) -> dict:  # type: ignore[type-arg]
    response = await stack.client.get("/api/v1/dashboard", headers=headers, params=params)
    assert response.status_code == 200, response.text
    data: dict = response.json()  # type: ignore[type-arg]
    return data


async def test_dashboard_aggregates_real_data(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset, "cleartext_http", "missing_csp")
    failing = (await _request(stack, analyst, project, asset)).json()
    await stack.client.post(
        f"/api/v1/projects/{project}/scans/{failing['id']}/cancel", headers=analyst
    )
    await _scan(stack, analyst, project, asset, "cleartext_http")  # resolves the CSP finding

    data = await _dashboard(stack, analyst)
    assert data["scope"] == {"project_id": None, "projects": 1}
    assert data["totals"]["assets"] == 1
    assert data["totals"]["active_findings"] == 1
    assert data["totals"]["active_scans"] == 0
    assert sum(data["risk_distribution"].values()) == 1
    assert list(data["risk_distribution"]) == ["critical", "high", "medium", "low", "info"]
    assert data["assets_by_exposure"] == {"external": 1, "internal": 0, "unknown": 0}
    today = data["scan_activity"][-1]
    assert len(data["scan_activity"]) == 14
    assert today["completed"] == 2
    assert today["cancelled"] == 1
    week = data["remediation"]["weekly"][-1]
    assert week["opened"] == 2
    assert week["resolved"] == 1
    assert data["remediation"]["by_status"]["resolved"] == 1
    assert data["remediation"]["closed_ratio"] == 0.5
    assert [f["title"] for f in data["recent_findings"]] == [
        "Web content served over cleartext HTTP"
    ]
    assert data["recent_findings"][0]["project_name"] == "Acme"
    assert data["posture"]["worst_project"]["name"] == "Acme"
    assert data["posture"]["score"] > 0
    assert data["projects"][0]["active"] == 1
    assert data["empty"] is False

    filtered = await _dashboard(stack, admin, project_id=project)
    assert filtered["totals"] == data["totals"]


async def test_dashboard_only_counts_accessible_projects(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset, "cleartext_http")
    outsider = await stack.user_headers("outsider@example.com", RoleName.SECURITY_ANALYST)

    data = await _dashboard(stack, outsider)
    assert data["empty"] is True
    assert data["totals"]["assets"] == 0
    assert data["recent_findings"] == []
    assert data["posture"]["worst_project"] is None
    response = await stack.client.get(
        "/api/v1/dashboard", headers=outsider, params={"project_id": project}
    )
    assert response.status_code == 404
    response = await stack.client.get(
        "/api/v1/dashboard", headers=admin, params={"project_id": str(uuid.uuid4())}
    )
    assert response.status_code == 404
    assert (await _dashboard(stack, admin))["totals"]["active_findings"] == 1


async def test_dashboard_requires_authentication(stack: ApiStack) -> None:
    for path in ("/api/v1/dashboard", "/api/v1/vulnerabilities", "/api/v1/reconnaissance"):
        assert (await stack.client.get(path)).status_code == 401


async def test_vulnerabilities_across_projects(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset, "cleartext_http", "missing_csp")
    outsider = await stack.user_headers("outsider@example.com", RoleName.SECURITY_ANALYST)
    viewer_headers = await stack.user_headers("viewer@example.com", RoleName.VIEWER)
    url = "/api/v1/vulnerabilities"

    page = (await stack.client.get(url, headers=analyst)).json()
    assert page["total"] == 2
    assert {f["project_name"] for f in page["items"]} == {"Acme"}
    assert {f["asset"] for f in page["items"]} == {"93.184.215.14"}
    scores = [f["risk_score"] for f in page["items"]]
    assert scores == sorted(scores, reverse=True)
    assert sum(page["by_severity"].values()) == 2

    one = (await stack.client.get(url, headers=analyst, params={"page_size": 1})).json()
    assert len(one["items"]) == 1
    assert one["total"] == 2
    none = (await stack.client.get(url, headers=analyst, params={"search": "zzz-no-match"})).json()
    assert none["total"] == 0
    wildcard = (await stack.client.get(url, headers=analyst, params={"search": "%"})).json()
    assert wildcard["total"] == 0  # LIKE wildcards are escaped
    sev = page["items"][0]["severity"]
    filtered = (await stack.client.get(url, headers=analyst, params={"severity": sev})).json()
    assert filtered["total"] == page["by_severity"][sev]

    # Isolation: foreign project → empty list / 404; admin sees everything.
    assert (await stack.client.get(url, headers=outsider)).json()["total"] == 0
    assert (await stack.client.get(url, headers=viewer_headers)).json()["total"] == 0
    assert (
        await stack.client.get(url, headers=outsider, params={"project_id": project})
    ).status_code == 404
    assert (await stack.client.get(url, headers=admin)).json()["total"] == 2
    assert (
        await stack.client.get(url, headers=analyst, params={"severity": "bogus"})
    ).status_code == 422


async def test_reconnaissance_overview(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset, "cleartext_http")
    outsider = await stack.user_headers("outsider@example.com", RoleName.SECURITY_ANALYST)
    url = "/api/v1/reconnaissance"

    data = (await stack.client.get(url, headers=analyst)).json()
    assert data["empty"] is False
    assert data["assets_total"] == 1
    assert data["assets_new_7d"] == 1
    assert data["assets_by_type"]["ip_address"] == 1
    assert data["recent_assets"][0]["value"] == "93.184.215.14"
    assert data["recent_assets"][0]["project_name"] == "Acme"
    assert sum(data["scans_30d_by_scanner"].values()) >= 1
    assert data["recent_scans"][0]["project_name"] == "Acme"

    hidden = (await stack.client.get(url, headers=outsider)).json()
    assert hidden["empty"] is True
    assert hidden["assets_total"] == 0
    assert hidden["recent_assets"] == []
    assert hidden["recent_scans"] == []
    assert (
        await stack.client.get(url, headers=outsider, params={"project_id": project})
    ).status_code == 404
    assert (await stack.client.get(url, headers=admin)).json()["assets_total"] == 1
