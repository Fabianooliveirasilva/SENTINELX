"""Findings: ingestion from scans, deduplication, auto-resolution, regressions, triage."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

import pytest
from sqlalchemy import text

from app.core.permissions import RoleName
from sentinelx_security.scanners import (
    Observation,
    RawOutput,
    ScanContext,
    Scanner,
    ScannerName,
)
from sentinelx_security.scope import AssetType, Technique
from tests.integration.conftest import ApiStack
from tests.integration.test_scans import _asset, _request, _run_worker, _setup

pytestmark = pytest.mark.integration


class FlagScanner(Scanner):
    """Emits one http_endpoint observation per pinned address with the given flags."""

    name: ClassVar[ScannerName] = ScannerName.NMAP
    technique: ClassVar[Technique] = Technique.ACTIVE
    description: ClassVar[str] = "fake"
    profiles: ClassVar[Mapping[str, str]] = {"quick": "q", "standard": "s"}
    default_profile: ClassVar[str] = "quick"
    supported_asset_types = frozenset({AssetType.IP_ADDRESS})

    def __init__(self, *flags: str) -> None:
        self.flags = flags

    async def execute(self, ctx: ScanContext) -> RawOutput:
        return RawOutput(data=[a.compressed for a in ctx.pinned_addresses])

    def normalize_results(self, raw: RawOutput) -> list[Observation]:
        return [
            Observation("http_endpoint", f"{a} https://x/", {"server": "<b>x</b>"}, self.flags)
            for a in raw.data
        ]


async def _scan(
    stack: ApiStack, headers: dict[str, str], project: str, asset: str, *flags: str, **body: Any
) -> str:
    job = (await _request(stack, headers, project, asset, **body)).json()
    assert await _run_worker(stack, job["id"], FlagScanner(*flags)) == "completed"
    return str(job["id"])


async def _findings(stack: ApiStack, headers: dict[str, str], project: str, **params: Any) -> Any:
    response = await stack.client.get(
        f"/api/v1/projects/{project}/findings", headers=headers, params=params
    )
    assert response.status_code == 200, response.text
    return response.json()


async def test_scan_creates_deduplicated_findings(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    job = await _scan(stack, analyst, project, asset, "cleartext_http", "missing_csp", "unknown")

    page = await _findings(stack, analyst, project)
    assert page["total"] == 2
    assert [f["rule_id"] for f in page["items"]] == ["http.cleartext_http", "http.missing_csp"]
    first = page["items"][0]
    assert first["severity"] == "medium"
    assert first["status"] == "open"
    assert first["source"] == "nmap"
    assert first["cwe"] == 319
    assert first["last_scan_job_id"] == job

    detail = (
        await stack.client.get(
            f"/api/v1/projects/{project}/findings/{first['id']}", headers=analyst
        )
    ).json()
    assert detail["remediation"]
    assert detail["occurrences"][0]["scan_job_id"] == job
    assert detail["occurrences"][0]["observation"]["data"]["server"] == "<b>x</b>"
    assert detail["history"][0]["to_status"] == "open"

    scan = (
        await stack.client.get(f"/api/v1/projects/{project}/scans/{job}", headers=analyst)
    ).json()
    assert scan["summary"]["findings"] == {"new": 2, "updated": 0, "reopened": 0, "resolved": 0}

    await _scan(stack, analyst, project, asset, "cleartext_http", "missing_csp")
    page = await _findings(stack, analyst, project)
    assert page["total"] == 2
    assert {f["occurrence_count"] for f in page["items"]} == {2}

    summary = (
        await stack.client.get(f"/api/v1/projects/{project}/findings/summary", headers=analyst)
    ).json()
    assert summary["active_by_severity"]["medium"] == 1
    assert summary["active_by_severity"]["low"] == 1
    assert summary["by_status"]["open"] == 2


async def test_auto_resolution_and_regression(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset, "cleartext_http", "missing_csp")

    # A different profile does not resolve findings of another profile.
    await _scan(stack, analyst, project, asset, profile="standard")
    assert (await _findings(stack, analyst, project, active="true"))["total"] == 2

    fixed = await _scan(stack, analyst, project, asset, "cleartext_http")
    resolved = (await _findings(stack, analyst, project, status="resolved"))["items"]
    assert [f["rule_id"] for f in resolved] == ["http.missing_csp"]
    assert resolved[0]["resolved_at"]
    scan = (
        await stack.client.get(f"/api/v1/projects/{project}/scans/{fixed}", headers=analyst)
    ).json()
    assert scan["summary"]["findings"]["resolved"] == 1

    await _scan(stack, analyst, project, asset, "cleartext_http", "missing_csp")
    csp = (await _findings(stack, analyst, project, search="Content-Security"))["items"][0]
    assert csp["status"] == "open"
    assert "Regression" in csp["status_reason"]
    detail = (
        await stack.client.get(f"/api/v1/projects/{project}/findings/{csp['id']}", headers=analyst)
    ).json()
    assert [h["to_status"] for h in detail["history"]] == ["open", "resolved", "open"]


async def test_triage_and_suppression(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset, "missing_csp")
    finding = (await _findings(stack, analyst, project))["items"][0]
    url = f"/api/v1/projects/{project}/findings/{finding['id']}/status"

    viewer = await stack.create_user("viewer@example.com")
    await stack.client.post(
        f"/api/v1/projects/{project}/members", headers=admin, json={"user_id": str(viewer.id)}
    )
    viewer_headers = await stack.login(viewer.email)
    assert (await _findings(stack, viewer_headers, project))["total"] == 1
    assert (
        await stack.client.post(url, headers=viewer_headers, json={"status": "acknowledged"})
    ).status_code == 403

    missing_reason = await stack.client.post(
        url, headers=analyst, json={"status": "false_positive"}
    )
    assert missing_reason.status_code == 422
    ok = await stack.client.post(
        url, headers=analyst, json={"status": "false_positive", "reason": "CSP set by CDN"}
    )
    assert ok.status_code == 200
    assert ok.json()["status"] == "false_positive"
    assert (
        await stack.client.post(
            url, headers=analyst, json={"status": "false_positive", "reason": "again"}
        )
    ).status_code == 409

    # Suppressed findings are neither reopened nor auto-resolved by later scans.
    await _scan(stack, analyst, project, asset, "missing_csp")
    await _scan(stack, analyst, project, asset)
    detail = (
        await stack.client.get(
            f"/api/v1/projects/{project}/findings/{finding['id']}", headers=analyst
        )
    ).json()
    assert detail["status"] == "false_positive"
    assert detail["history"][0]["changed_by_email"] == "analyst@example.com"
    async with stack.app.state.session_factory() as session:
        actions = [
            r[0]
            for r in await session.execute(
                text("SELECT action FROM audit_logs WHERE action LIKE 'finding.%'")
            )
        ]
    assert actions == ["finding.status_changed"]


async def test_findings_are_project_isolated(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset, "missing_csp")
    finding = (await _findings(stack, analyst, project))["items"][0]
    outsider = await stack.user_headers("outsider@example.com", RoleName.SECURITY_ANALYST)
    assert (
        await stack.client.get(f"/api/v1/projects/{project}/findings", headers=outsider)
    ).status_code == 404
    assert (
        await stack.client.get(
            f"/api/v1/projects/{project}/findings/{finding['id']}", headers=outsider
        )
    ).status_code == 404
