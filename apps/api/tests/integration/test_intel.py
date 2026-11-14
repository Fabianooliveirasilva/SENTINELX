"""Threat intelligence: inventory, CVE correlation lifecycle, NVD refresh, KEV, API."""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest
from sqlalchemy import text

from app.core.permissions import RoleName
from app.services.intel import apply_kev, upsert_cves
from sentinelx_security.intel.nvd import NvdClient, parse_kev, parse_page
from sentinelx_security.scanners import Observation, RawOutput, ScanContext, Scanner, ScannerName
from sentinelx_security.scope import AssetType, Technique
from sentinelx_workers.tasks.intel import enrich_job, refresh
from tests.integration.conftest import ApiStack
from tests.integration.test_scans import _asset, _request, _run_worker, _setup

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[4] / "security-engine" / "tests" / "fixtures"


def nvd_payload() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / "nvd_page.json").read_text())
    return data


class TechScanner(Scanner):
    name: ClassVar[ScannerName] = ScannerName.NMAP
    technique: ClassVar[Technique] = Technique.ACTIVE
    description: ClassVar[str] = "fake"
    profiles: ClassVar[Mapping[str, str]] = {"quick": "q"}
    default_profile: ClassVar[str] = "quick"
    supported_asset_types = frozenset({AssetType.IP_ADDRESS})

    def __init__(self, **versions: str) -> None:
        self.versions = versions

    async def execute(self, ctx: ScanContext) -> RawOutput:
        return RawOutput(data=None)

    def normalize_results(self, raw: RawOutput) -> list[Observation]:
        return [
            Observation(
                "technology", f"t {name}", {"name": name, "version": v, "url": "https://x/"}
            )
            for name, v in self.versions.items()
        ]


async def _seed_cves(stack: ApiStack) -> None:
    async with stack.app.state.session_factory() as session:
        await upsert_cves(session, parse_page(nvd_payload())[0])
        await session.commit()


async def _scan(
    stack: ApiStack, headers: dict[str, str], project: str, asset: str, **versions: str
) -> str:
    job = (await _request(stack, headers, project, asset)).json()
    assert await _run_worker(stack, job["id"], TechScanner(**versions)) == "completed"
    return str(job["id"])


async def _cve_findings(
    stack: ApiStack, headers: dict[str, str], project: str, **params: Any
) -> list[dict[str, Any]]:
    page = (
        await stack.client.get(
            f"/api/v1/projects/{project}/findings",
            headers=headers,
            params={"source": "intel", **params},
        )
    ).json()
    return list(page["items"])


async def test_scan_correlates_versions_and_resolves_after_upgrade(stack: ApiStack) -> None:
    await _seed_cves(stack)
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    job = await _scan(stack, analyst, project, asset, Apache="2.4.49", jQuery="3.5.1")

    findings = await _cve_findings(stack, analyst, project)
    assert [(f["rule_id"], f["severity"], f["confidence"]) for f in findings] == [
        ("cve.CVE-2021-41773", "critical", "tentative")
    ]
    assert findings[0]["category"] == "cve"
    scan = (
        await stack.client.get(f"/api/v1/projects/{project}/scans/{job}", headers=analyst)
    ).json()
    assert scan["summary"]["software"] == 2
    assert scan["summary"]["cve_findings"]["new"] == 1

    software = (
        await stack.client.get(f"/api/v1/projects/{project}/software", headers=analyst)
    ).json()
    assert {(s["name"], s["version"], s["correlatable"]) for s in software} == {
        ("Apache", "2.4.49", True),
        ("jQuery", "3.5.1", True),
    }

    # Upgrade: the next scan reports a fixed version → the CVE finding resolves.
    await _scan(stack, analyst, project, asset, Apache="2.4.58", jQuery="3.4.1")
    resolved = await _cve_findings(stack, analyst, project, status="resolved")
    assert [f["rule_id"] for f in resolved] == ["cve.CVE-2021-41773"]
    active = await _cve_findings(stack, analyst, project, active="true")
    assert [f["rule_id"] for f in active] == ["cve.CVE-2020-11022"]
    software = (
        await stack.client.get(f"/api/v1/projects/{project}/software", headers=analyst)
    ).json()
    assert {s["version"] for s in software} == {"2.4.58", "3.4.1"}  # inventory replaced


async def test_versionless_components_never_match(stack: ApiStack) -> None:
    await _seed_cves(stack)
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset, Apache="", jQuery="unknown")
    assert await _cve_findings(stack, analyst, project) == []


async def test_late_nvd_refresh_recorrelates_existing_inventory(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    job = await _scan(stack, analyst, project, asset, Apache="2.4.49")
    assert await _cve_findings(stack, analyst, project) == []  # nothing stored yet

    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=nvd_payload())

    client = NvdClient(transport=httpx.MockTransport(handler), min_interval=0)
    async with stack.app.state.session_factory() as session:
        result = await enrich_job(uuid.UUID(job), stack.settings, client, session)
        # A second run inside the TTL does not hit NVD again.
        again = await enrich_job(uuid.UUID(job), stack.settings, client, session)
    assert result["refreshed"] == 1
    assert result["assets_recorrelated"] == 1
    assert again["refreshed"] == 0
    assert [r.url.params["virtualMatchString"] for r in requests] == [
        "cpe:2.3:*:apache:http_server"
    ]

    findings = await _cve_findings(stack, analyst, project)
    assert [f["rule_id"] for f in findings] == ["cve.CVE-2021-41773"]
    detail = (
        await stack.client.get(
            f"/api/v1/projects/{project}/findings/{findings[0]['id']}", headers=analyst
        )
    ).json()
    assert "intelligence re-correlation" in detail["history"][0]["reason"]
    assert detail["references"][0] == "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"


async def test_refresh_errors_are_recorded_not_raised(stack: ApiStack) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    client = NvdClient(transport=httpx.MockTransport(down), min_interval=0, max_retries=0)
    async with stack.app.state.session_factory() as session:
        result = await refresh([("apache", "http_server")], client, session)
    assert result["errors"] == {"apache:http_server": "source_error"}
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)
    status = (await stack.client.get("/api/v1/intelligence/status", headers=admin)).json()
    assert status["products"][0]["status"] == "error"


async def test_cve_search_detail_kev_and_status(stack: ApiStack) -> None:
    await _seed_cves(stack)
    async with stack.app.state.session_factory() as session:
        flagged = await apply_kev(
            session, parse_kev(json.loads((FIXTURES / "kev_sample.json").read_text()))
        )
        await session.commit()
    assert flagged == 1
    viewer = await stack.user_headers("viewer@example.com")

    page = (await stack.client.get("/api/v1/intelligence/cves", headers=viewer)).json()
    assert [c["id"] for c in page["items"]] == ["CVE-2021-41773", "CVE-2020-11022"]  # by score
    kev = (
        await stack.client.get("/api/v1/intelligence/cves", headers=viewer, params={"kev": "true"})
    ).json()
    assert [c["id"] for c in kev["items"]] == ["CVE-2021-41773"]
    by_product = (
        await stack.client.get(
            "/api/v1/intelligence/cves",
            headers=viewer,
            params={"vendor": "jquery", "product": "jquery"},
        )
    ).json()
    assert [c["id"] for c in by_product["items"]] == ["CVE-2020-11022"]
    text_search = (
        await stack.client.get(
            "/api/v1/intelligence/cves", headers=viewer, params={"search": "cve-2020"}
        )
    ).json()
    assert text_search["total"] == 1

    detail = (
        await stack.client.get("/api/v1/intelligence/cves/cve-2021-41773", headers=viewer)
    ).json()
    assert detail["cvss_score"] == 9.8
    assert detail["kev_added_on"]
    assert any(
        m["product"] == "http_server" and m["version"] == "2.4.49" for m in detail["matches"]
    )
    assert (
        await stack.client.get("/api/v1/intelligence/cves/CVE-1999-0001", headers=viewer)
    ).status_code == 404
    assert (
        await stack.client.get("/api/v1/intelligence/cves/not-a-cve", headers=viewer)
    ).status_code == 422

    status = (await stack.client.get("/api/v1/intelligence/status", headers=viewer)).json()
    assert status["cves"] == 2
    assert status["kev_cves"] == 1
    assert status["sources"][0]["name"] == "kev"
    assert status["nvd_api_key_configured"] is False


async def test_product_sync_requires_admin_and_is_audited(stack: ApiStack) -> None:
    admin, analyst, _ = await _setup(stack)
    body = {"vendor": "Apache", "product": "http_server"}
    assert (
        await stack.client.post("/api/v1/intelligence/products/sync", headers=analyst, json=body)
    ).status_code == 403
    response = await stack.client.post(
        "/api/v1/intelligence/products/sync", headers=admin, json=body
    )
    assert response.status_code == 202
    assert response.json()["vendor"] == "apache"
    assert response.json()["status"] == "pending"
    assert stack.intel_dispatcher.refreshes == 1
    bad = await stack.client.post(
        "/api/v1/intelligence/products/sync", headers=admin, json={"vendor": "a b", "product": "x"}
    )
    assert bad.status_code == 422
    async with stack.app.state.session_factory() as session:
        actions = [r[0] for r in await session.execute(text("SELECT action FROM audit_logs"))]
    assert "intel.product_sync_requested" in actions


async def test_software_inventory_is_project_isolated(stack: ApiStack) -> None:
    *_, project = await _setup(stack)
    outsider = await stack.user_headers("outsider@example.com", RoleName.SECURITY_ANALYST)
    assert (
        await stack.client.get(f"/api/v1/projects/{project}/software", headers=outsider)
    ).status_code == 404
