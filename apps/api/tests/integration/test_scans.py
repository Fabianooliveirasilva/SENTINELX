"""Scan orchestration through the API and the worker-side lifecycle steps."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import pytest
from sqlalchemy import text

from app.core.config import Settings
from app.core.permissions import RoleName
from app.services.scans import record_outcome, start_job
from sentinelx_security.scanners import (
    Evidence,
    Observation,
    RawOutput,
    ScanContext,
    Scanner,
    ScannerName,
    ScanRequest,
    execute_scan,
)
from sentinelx_security.scope import AssetType, ScopeEngine, Technique
from tests.integration.conftest import ApiStack, integration_settings

pytestmark = pytest.mark.integration

NOW = datetime.now(UTC)


@pytest.fixture
def stack_settings() -> Settings:
    return integration_settings(max_concurrent_scans_per_project=2)


class FakeNmap(Scanner):
    """Stands in for the sandboxed scanner; records the pinned addresses it got."""

    name: ClassVar[ScannerName] = ScannerName.NMAP
    technique: ClassVar[Technique] = Technique.ACTIVE
    description: ClassVar[str] = "fake"
    profiles: ClassVar[Mapping[str, str]] = {"quick": "q"}
    default_profile: ClassVar[str] = "quick"
    supported_asset_types = frozenset({AssetType.IP_ADDRESS, AssetType.DOMAIN})

    def __init__(self) -> None:
        self.contexts: list[ScanContext] = []

    async def execute(self, ctx: ScanContext) -> RawOutput:
        self.contexts.append(ctx)
        return RawOutput(data=[a.compressed for a in ctx.pinned_addresses])

    def normalize_results(self, raw: RawOutput) -> list[Observation]:
        return [
            Observation("open_port", f"{a}:443/tcp", {"port": 443}, ("cleartext",))
            for a in raw.data
        ]

    def record_evidence(self, raw: RawOutput) -> list[Evidence]:
        return [Evidence.bounded("nmap xml", "<nmaprun>" + "<script>x</script>" + "</nmaprun>")]


async def _setup(stack: ApiStack) -> tuple[dict[str, str], dict[str, str], str]:
    admin = await stack.user_headers("admin@example.com", RoleName.ADMIN)
    analyst = await stack.create_user("analyst@example.com", role=RoleName.SECURITY_ANALYST)
    project = (
        await stack.client.post("/api/v1/projects", headers=admin, json={"name": "Acme"})
    ).json()
    await stack.client.post(
        f"/api/v1/projects/{project['id']}/members",
        headers=admin,
        json={"user_id": str(analyst.id)},
    )
    return admin, await stack.login(analyst.email), project["id"]


async def _asset(
    stack: ApiStack,
    headers: dict[str, str],
    project: str,
    *,
    type: str = "ip_address",
    value: str = "93.184.215.14",
    allow_active: bool = True,
    ip_ranges: tuple[str, ...] = ("93.184.215.0/24",),
) -> str:
    response = await stack.client.post(
        f"/api/v1/projects/{project}/assets", headers=headers, json={"type": type, "value": value}
    )
    assert response.status_code == 201, response.text
    asset_id: str = response.json()["id"]
    response = await stack.client.post(
        f"/api/v1/projects/{project}/assets/{asset_id}/authorizations",
        headers=headers,
        json={
            "authorized_by": "Jane Owner",
            "organization": "Acme Corp",
            "reference": "SOW-1",
            "valid_from": (NOW - timedelta(hours=1)).isoformat(),
            "valid_until": (NOW + timedelta(days=30)).isoformat(),
            "allow_active": allow_active,
            "ip_ranges": list(ip_ranges) if allow_active else [],
        },
    )
    assert response.status_code == 201, response.text
    return asset_id


async def _request(
    stack: ApiStack, headers: dict[str, str], project: str, asset: str, **body: Any
) -> Any:
    return await stack.client.post(
        f"/api/v1/projects/{project}/scans",
        headers=headers,
        json={"asset_id": asset, "scanner": "nmap", **body},
    )


async def _run_worker(stack: ApiStack, job_id: str, scanner: Scanner | None = None) -> str | None:
    """Simulate the chain: orchestrator start → sandbox execute → orchestrator record."""
    async with stack.app.state.session_factory() as session:
        request = await start_job(session, uuid.UUID(job_id), stack.settings)
    outcome = None
    if request is not None:
        engine: ScopeEngine = stack.app.state.scope_engine
        result = await execute_scan(
            ScanRequest.from_dict(request),
            engine,
            {ScannerName.NMAP: scanner or FakeNmap()},
        )
        outcome = result.to_dict()
    async with stack.app.state.session_factory() as session:
        return await record_outcome(session, uuid.UUID(job_id), outcome)


async def _audit_actions(stack: ApiStack) -> list[str]:
    async with stack.app.state.session_factory() as session:
        rows = await session.execute(text("SELECT action FROM audit_logs ORDER BY created_at"))
        return [r[0] for r in rows]


# ----------------------------------------------------------------------------- catalog


async def test_scanner_catalog(stack: ApiStack) -> None:
    viewer = await stack.user_headers("viewer@example.com")
    response = await stack.client.get("/api/v1/scanners", headers=viewer)
    assert response.status_code == 200
    catalog = {s["name"]: s for s in response.json()}
    assert set(catalog) == {"dns", "subdomains", "tls", "nmap", "http", "nuclei", "zap"}
    zap_profiles = {p["name"]: p["technique"] for p in catalog["zap"]["profiles"]}
    assert zap_profiles == {"baseline": "active", "full": "intrusive"}
    assert catalog["nmap"]["technique"] == "active"
    assert catalog["subdomains"]["technique"] == "passive"
    assert {p["name"] for p in catalog["nmap"]["profiles"]} == {"quick", "standard", "web"}


# ----------------------------------------------------------------------------- lifecycle


async def test_scan_lifecycle_end_to_end(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)

    response = await _request(stack, analyst, project, asset)
    assert response.status_code == 202, response.text
    job = response.json()
    assert job["status"] == "queued"
    assert job["target"] == "93.184.215.14"
    assert job["profile"] == "quick"
    assert job["technique"] == "active"
    assert stack.dispatcher.dispatched == [job["id"]]

    scanner = FakeNmap()
    assert await _run_worker(stack, job["id"], scanner) == "completed"
    assert [a.compressed for a in scanner.contexts[0].pinned_addresses] == ["93.184.215.14"]

    detail = (
        await stack.client.get(f"/api/v1/projects/{project}/scans/{job['id']}", headers=analyst)
    ).json()
    assert detail["status"] == "completed"
    assert detail["pinned_addresses"] == ["93.184.215.14"]
    assert detail["scope_decision"]["allowed"] is True
    assert detail["summary"]["by_kind"] == {"open_port": 1}
    assert detail["summary"]["attention"] == {"cleartext": 1}
    assert detail["results"][0]["key"] == "93.184.215.14:443/tcp"
    # Evidence is returned verbatim as text; rendering safety is the UI's job.
    assert "<script>" in detail["evidence"][0]["content"]
    assert detail["tool_versions"]["sentinelx-security"]
    assert detail["started_at"]
    assert detail["finished_at"]

    listing = (
        await stack.client.get(
            f"/api/v1/projects/{project}/scans", headers=analyst, params={"status": "completed"}
        )
    ).json()
    assert listing["total"] == 1
    actions = [a for a in await _audit_actions(stack) if a.startswith("scan.")]
    assert actions == ["scan.requested", "scan.completed"]


async def test_scope_is_rechecked_at_execution_time(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    job = (await _request(stack, analyst, project, asset)).json()

    # The authorization is revoked after the job was queued.
    async with stack.app.state.session_factory() as session:
        await session.execute(text("UPDATE asset_authorizations SET revoked_at = now()"))
        await session.commit()

    scanner = FakeNmap()
    assert await _run_worker(stack, job["id"], scanner) == "failed"
    assert scanner.contexts == []  # the scanner never ran
    detail = (
        await stack.client.get(f"/api/v1/projects/{project}/scans/{job['id']}", headers=analyst)
    ).json()
    assert detail["error_code"] == "scope_denied"
    assert detail["scope_decision"]["allowed"] is False
    assert detail["results"] == []
    assert (await _audit_actions(stack))[-1] == "scan.scope_denied"


async def test_rebinding_domain_is_denied_at_execution(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project, type="domain", value="rebind.example.com")
    job = (await _request(stack, analyst, project, asset)).json()
    assert job["status"] == "queued"  # preflight is static (no DNS)
    assert await _run_worker(stack, job["id"]) == "failed"
    detail = (
        await stack.client.get(f"/api/v1/projects/{project}/scans/{job['id']}", headers=analyst)
    ).json()
    assert detail["error_code"] == "scope_denied"
    assert detail["pinned_addresses"] == ["93.184.215.14"]
    loopback = next(a for a in detail["scope_decision"]["addresses"] if a["address"] == "127.0.0.1")
    assert loopback["allowed"] is False


# ----------------------------------------------------------------------------- preflight


async def test_rbac_and_tenancy(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    viewer = await stack.create_user("viewer@example.com")
    await stack.client.post(
        f"/api/v1/projects/{project}/members", headers=admin, json={"user_id": str(viewer.id)}
    )
    viewer_headers = await stack.login(viewer.email)
    outsider = await stack.user_headers("outsider@example.com", RoleName.SECURITY_ANALYST)

    assert (await _request(stack, viewer_headers, project, asset)).status_code == 403
    assert (await _request(stack, outsider, project, asset)).status_code == 404
    assert (
        await stack.client.get(f"/api/v1/projects/{project}/scans", headers=outsider)
    ).status_code == 404
    assert (
        await stack.client.get(f"/api/v1/projects/{project}/scans", headers=viewer_headers)
    ).status_code == 200
    assert stack.dispatcher.dispatched == []


async def test_passive_authorization_blocks_active_scanners(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(
        stack, analyst, project, type="domain", value="example.com", allow_active=False
    )

    denied = await _request(stack, analyst, project, asset)
    assert denied.status_code == 422
    assert "not authorized for active scanning" in denied.json()["error"]["message"]
    assert (await _audit_actions(stack))[-1] == "scan.rejected"

    passive = await _request(stack, analyst, project, asset, scanner="dns")
    assert passive.status_code == 202, passive.text
    assert passive.json()["technique"] == "passive"


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ({"scanner": "dns"}, "does not support ip_address"),
        ({"scanner": "nmap", "profile": "aggressive"}, "Unknown profile"),
        ({"scanner": "metasploit"}, "Unknown scanner"),
    ],
)
async def test_invalid_requests(stack: ApiStack, body: dict[str, str], fragment: str) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    response = await _request(stack, analyst, project, asset, **body)
    assert response.status_code == 422
    assert fragment in response.json()["error"]["message"]


async def test_user_flags_are_not_accepted(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    response = await _request(stack, analyst, project, asset, arguments="-sS -p-")
    assert response.status_code == 422
    response = await _request(stack, analyst, project, asset, profile="quick; rm -rf /")
    assert response.status_code == 422


async def test_concurrency_quota(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    for _ in range(2):
        assert (await _request(stack, analyst, project, asset)).status_code == 202
    response = await _request(stack, analyst, project, asset)
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "quota_exceeded"


async def test_broker_failure_marks_job_failed(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    stack.dispatcher.fail = True
    response = await _request(stack, analyst, project, asset)
    assert response.status_code == 503
    listing = (await stack.client.get(f"/api/v1/projects/{project}/scans", headers=analyst)).json()
    assert listing["items"][0]["status"] == "failed"
    assert listing["items"][0]["error_code"] == "dispatch_failed"


# ----------------------------------------------------------------------------- cancel / stop


async def test_cancel_queued_scan(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    job = (await _request(stack, analyst, project, asset)).json()

    url = f"/api/v1/projects/{project}/scans/{job['id']}/cancel"
    response = await stack.client.post(url, headers=analyst)
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    assert stack.dispatcher.revoked == [f"exec-{job['id']}"]
    assert (await stack.client.post(url, headers=analyst)).status_code == 409
    # The orchestrator skips the cancelled job; nothing is scanned or recorded.
    scanner = FakeNmap()
    assert await _run_worker(stack, job["id"], scanner) is None
    assert scanner.contexts == []


async def test_late_results_do_not_overwrite_a_cancellation(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    job = (await _request(stack, analyst, project, asset)).json()
    async with stack.app.state.session_factory() as session:
        request = await start_job(session, uuid.UUID(job["id"]), stack.settings)
    assert request is not None
    await stack.client.post(f"/api/v1/projects/{project}/scans/{job['id']}/cancel", headers=analyst)
    async with stack.app.state.session_factory() as session:
        status = await record_outcome(
            session, uuid.UUID(job["id"]), {"status": "completed", "observations": []}
        )
    assert status is None
    detail = (
        await stack.client.get(f"/api/v1/projects/{project}/scans/{job['id']}", headers=analyst)
    ).json()
    assert detail["status"] == "cancelled"


async def test_emergency_stop(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    job = (await _request(stack, analyst, project, asset)).json()

    body = {"reason": "Customer reported impact"}
    assert (
        await stack.client.post("/api/v1/scans/emergency-stop", headers=analyst, json=body)
    ).status_code == 403
    response = await stack.client.post("/api/v1/scans/emergency-stop", headers=admin, json=body)
    assert response.status_code == 200
    assert response.json()["halted"] is True
    assert response.json()["cancelled_jobs"] == 1
    assert stack.dispatcher.revoked == [f"exec-{job['id']}"]

    controls = (await stack.client.get("/api/v1/scans/controls", headers=analyst)).json()
    assert controls["halted"] is True
    assert controls["reason"] == "Customer reported impact"
    assert controls["updated_by"] == "admin@example.com"

    blocked = await _request(stack, analyst, project, asset)
    assert blocked.status_code == 409
    assert "emergency stop" in blocked.json()["error"]["message"]

    assert (await stack.client.post("/api/v1/scans/resume", headers=admin)).status_code == 200
    assert (await stack.client.post("/api/v1/scans/resume", headers=admin)).status_code == 409
    assert (await _request(stack, analyst, project, asset)).status_code == 202
    actions = await _audit_actions(stack)
    assert "scan.emergency_stop" in actions
    assert "scan.resumed" in actions


async def test_queued_job_is_skipped_while_halted(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    job = (await _request(stack, analyst, project, asset)).json()
    async with stack.app.state.session_factory() as session:
        await session.execute(
            text(
                "INSERT INTO platform_settings (key, value) "
                "VALUES ('scans.halted', '{\"halted\": true}')"
            )
        )
        await session.commit()
    assert await _run_worker(stack, job["id"]) is None
    detail = (
        await stack.client.get(f"/api/v1/projects/{project}/scans/{job['id']}", headers=analyst)
    ).json()
    assert detail["status"] == "cancelled"
    assert detail["error_code"] == "emergency_stop"


async def test_stale_jobs_expire(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    job = (await _request(stack, analyst, project, asset)).json()
    async with stack.app.state.session_factory() as session:
        await session.execute(
            text("UPDATE scan_jobs SET queued_at = now() - interval '2 days' WHERE id = :id"),
            {"id": job["id"]},
        )
        await session.commit()
    detail = (
        await stack.client.get(f"/api/v1/projects/{project}/scans/{job['id']}", headers=analyst)
    ).json()
    assert detail["status"] == "failed"
    assert detail["error_code"] == "queue_timeout"
    # Expired jobs no longer count against the concurrency quota.
    assert (await _request(stack, analyst, project, asset)).status_code == 202


async def test_celery_orchestrator_tasks_against_the_database(stack: ApiStack) -> None:
    """The real task wrappers (own engine + asyncio.run), run off the test loop."""
    from sentinelx_workers.tasks import scans as tasks

    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    job = (await _request(stack, analyst, project, asset)).json()

    request = await asyncio.to_thread(tasks.start.run, job["id"])
    assert request is not None
    assert request["target"] == "93.184.215.14"
    assert request["assets"][0]["authorizations"][0]["allow_active"] is True
    assert await asyncio.to_thread(tasks.start.run, job["id"]) is None  # not re-startable

    outcome = (
        await execute_scan(
            ScanRequest.from_dict(request),
            stack.app.state.scope_engine,
            {ScannerName.NMAP: FakeNmap()},
        )
    ).to_dict()
    assert await asyncio.to_thread(tasks.record.run, outcome, job["id"]) == "completed"
    assert await asyncio.to_thread(tasks.expire_stale.run) == 0


async def test_intrusive_profile_requires_an_intrusive_authorization(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    denied = await _request(stack, analyst, project, asset, scanner="zap", profile="full")
    assert denied.status_code == 422
    assert "not authorized for intrusive scanning" in denied.json()["error"]["message"]

    baseline = await _request(stack, analyst, project, asset, scanner="zap")
    assert baseline.status_code == 202
    assert baseline.json()["technique"] == "active"
    assert stack.dispatcher.dispatched == [baseline.json()["id"]]

    # Only administrators can record intrusive authorizations.
    response = await stack.client.post(
        f"/api/v1/projects/{project}/assets/{asset}/authorizations",
        headers=admin,
        json={
            "authorized_by": "Jane Owner",
            "organization": "Acme Corp",
            "reference": "SOW-2-PENTEST",
            "valid_from": (NOW - timedelta(hours=1)).isoformat(),
            "valid_until": (NOW + timedelta(days=7)).isoformat(),
            "allow_active": True,
            "allow_intrusive": True,
            "ip_ranges": ["93.184.215.0/24"],
        },
    )
    assert response.status_code == 201, response.text
    full = await _request(stack, analyst, project, asset, scanner="zap", profile="full")
    assert full.status_code == 202, full.text
    assert full.json()["technique"] == "intrusive"
