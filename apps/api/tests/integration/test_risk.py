"""Risk engine: scoring on ingestion, rescoring triggers, weights, posture, trend."""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest
from sqlalchemy import text

from app.core.permissions import RoleName
from sentinelx_security.intel.epss import EpssScore
from sentinelx_workers.tasks.intel import sync_epss_for_findings
from sentinelx_workers.tasks.risk import daily
from tests.integration.conftest import ApiStack
from tests.integration.test_findings import _scan
from tests.integration.test_intel import _scan as _tech_scan
from tests.integration.test_intel import _seed_cves
from tests.integration.test_scans import _asset, _setup

pytestmark = pytest.mark.integration


async def _findings(stack: ApiStack, headers: dict[str, str], project: str, **params: Any) -> Any:
    return (
        await stack.client.get(
            f"/api/v1/projects/{project}/findings", headers=headers, params=params
        )
    ).json()["items"]


async def _detail(stack: ApiStack, headers: dict[str, str], project: str, fid: str) -> Any:
    return (
        await stack.client.get(f"/api/v1/projects/{project}/findings/{fid}", headers=headers)
    ).json()


async def test_findings_are_scored_and_sorted_by_risk(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(
        stack, analyst, project, asset, "missing_csp", "cleartext_http", "missing_referrer_policy"
    )

    items = await _findings(stack, analyst, project)
    assert [f["rule_id"] for f in items] == [
        "http.cleartext_http",
        "http.missing_csp",
        "http.missing_referrer_policy",
    ]
    scores = [f["risk_score"] for f in items]
    assert scores == sorted(scores, reverse=True)
    # medium (55) x confirmed (1.1) x medium criticality (1.0) x external exposure (1.0)
    assert items[0]["risk_score"] == 60.5
    assert items[0]["risk_band"] == "high"

    detail = await _detail(stack, analyst, project, items[0]["id"])
    assert round(sum(f["points"] for f in detail["risk_factors"]), 1) == detail["risk_score"]
    assert detail["risk_model_version"] == "1.0.0"
    assert detail["risk_explanation"].startswith("High risk (60.5/100): starts at 55")
    assert [h["trigger"] for h in detail["risk_history"]] == ["scan"]

    only_low = await _findings(stack, analyst, project, risk_band="low")
    assert [f["rule_id"] for f in only_low] == ["http.missing_csp"]


async def test_asset_context_changes_rescore(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset, "cleartext_http")
    (before,) = await _findings(stack, analyst, project)

    response = await stack.client.patch(
        f"/api/v1/projects/{project}/assets/{asset}",
        headers=analyst,
        json={"criticality": "critical"},
    )
    assert response.status_code == 200
    (after,) = await _findings(stack, analyst, project)
    assert after["risk_score"] == 78.7  # 55 x 1.1 x 1.3
    assert after["risk_band"] == "high"
    detail = await _detail(stack, analyst, project, after["id"])
    assert [h["trigger"] for h in detail["risk_history"]] == ["asset_updated", "scan"]
    assert before["risk_score"] < after["risk_score"]

    # Description-only edits do not rescore.
    await stack.client.patch(
        f"/api/v1/projects/{project}/assets/{asset}", headers=analyst, json={"description": "x"}
    )
    detail = await _detail(stack, analyst, project, after["id"])
    assert len(detail["risk_history"]) == 2


async def test_cve_findings_use_cvss_kev_and_epss(stack: ApiStack) -> None:
    await _seed_cves(stack)
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _tech_scan(stack, analyst, project, asset, Apache="2.4.49")
    (cve,) = await _findings(stack, analyst, project, source="intel")
    assert cve["cve_id"] == "CVE-2021-41773"
    detail = await _detail(stack, analyst, project, cve["id"])
    factors = {f["name"]: f for f in detail["risk_factors"]}
    assert factors["base"]["value"] == "CVSS 9.8"
    assert factors["confidence"]["effect"] == "x 0.8"  # tentative
    assert "known_exploited" in factors  # fixture CVE carries cisaExploitAdd
    assert "exploit_prediction" not in factors

    async def fake_fetch(ids: list[str], url: str) -> dict[str, EpssScore]:
        assert ids == ["CVE-2021-41773"]
        return {"CVE-2021-41773": EpssScore("CVE-2021-41773", 0.97, 0.99, date(2026, 11, 10))}

    async with stack.app.state.session_factory() as session:
        assert await sync_epss_for_findings(session, fetch=fake_fetch) == 1
    detail = await _detail(stack, analyst, project, cve["id"])
    factors = {f["name"]: f for f in detail["risk_factors"]}
    assert factors["exploit_prediction"]["value"] == "EPSS 0.970"


async def test_weights_are_admin_only_validated_audited_and_rescore(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset, "cleartext_http")

    model = (await stack.client.get("/api/v1/risk/model", headers=analyst)).json()
    assert model["weights"] == model["defaults"]
    assert model["bounds"]["kev_points"] == {"min": 0, "max": 50}
    assert "posture" in model["formula"].lower()

    body = {"weights": {"exposure_external": 1.5}}
    assert (
        await stack.client.put("/api/v1/risk/weights", headers=analyst, json=body)
    ).status_code == 403
    bad = await stack.client.put(
        "/api/v1/risk/weights", headers=admin, json={"weights": {"kev_points": 99}}
    )
    assert bad.status_code == 422
    assert "between" in bad.json()["error"]["message"]

    updated = await stack.client.put("/api/v1/risk/weights", headers=admin, json=body)
    assert updated.status_code == 200
    assert updated.json()["rescored"] == 1
    (finding,) = await _findings(stack, analyst, project)
    assert finding["risk_score"] == 90.8  # 55 x 1.1 x 1.5

    reset = await stack.client.post("/api/v1/risk/weights/reset", headers=admin)
    assert reset.json()["weights"]["exposure_external"] == 1.0
    (finding,) = await _findings(stack, analyst, project)
    assert finding["risk_score"] == 60.5
    async with stack.app.state.session_factory() as session:
        actions = [r[0] for r in await session.execute(text("SELECT action FROM audit_logs"))]
    assert "risk.weights_updated" in actions
    assert "risk.weights_reset" in actions


async def test_project_posture_top_risks_and_trend(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset, "cleartext_http", "missing_csp", "caa_missing")

    risk = (await stack.client.get(f"/api/v1/projects/{project}/risk", headers=analyst)).json()
    assert risk["posture"]["active"] == 2  # caa_missing is not an http_endpoint flag
    assert risk["posture"]["score"] >= 60.5
    assert risk["posture"]["counts"] == {"critical": 0, "high": 1, "medium": 0, "low": 1, "info": 0}
    assert risk["top_risks"][0]["rule_id"] == "http.cleartext_http"
    assert len(risk["trend"]) == 1
    assert risk["trend"][0]["score"] == risk["posture"]["score"]

    # Suppressing the worst finding lowers the posture immediately.
    worst = risk["top_risks"][0]
    await stack.client.post(
        f"/api/v1/projects/{project}/findings/{worst['id']}/status",
        headers=analyst,
        json={"status": "accepted_risk", "reason": "Compensating control"},
    )
    after = (await stack.client.get(f"/api/v1/projects/{project}/risk", headers=analyst)).json()
    assert after["posture"]["score"] < risk["posture"]["score"]
    assert after["trend"][-1]["score"] == after["posture"]["score"]

    outsider = await stack.user_headers("outsider@example.com", RoleName.SECURITY_ANALYST)
    assert (
        await stack.client.get(f"/api/v1/projects/{project}/risk", headers=outsider)
    ).status_code == 404


async def test_daily_rescoring_adds_the_exposure_window(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset, "cleartext_http")
    async with stack.app.state.session_factory() as session:
        await session.execute(
            text("UPDATE findings SET first_seen_at = now() - interval '100 days'")
        )
        await session.commit()
        result = await daily(session)
    assert result["changed"] == 1
    (finding,) = await _findings(stack, analyst, project)
    assert finding["risk_score"] == 67.5  # 60.5 + 7 (open > 90 days)
