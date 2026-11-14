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
