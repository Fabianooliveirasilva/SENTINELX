"""Reports: content, formats, integrity, AI labelling, scopes, permissions."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text

from app.core.permissions import RoleName
from app.services.reports import generate_report
from tests.integration.conftest import ApiStack
from tests.integration.test_ai import INJECTION, HostileScanner
from tests.integration.test_scans import _asset, _request, _run_worker, _setup

pytestmark = pytest.mark.integration


async def _scan(stack: ApiStack, headers: dict[str, str], project: str, asset: str) -> str:
    job = (await _request(stack, headers, project, asset)).json()
    assert await _run_worker(stack, job["id"], HostileScanner()) == "completed"
    return str(job["id"])


async def _report(
    stack: ApiStack, headers: dict[str, str], project: str, **body: Any
) -> dict[str, Any]:
    response = await stack.client.post(
        f"/api/v1/projects/{project}/reports", headers=headers, json=body
    )
    assert response.status_code == 202, response.text
    report: dict[str, Any] = response.json()
    assert report["status"] == "pending"
    async with stack.app.state.session_factory() as session:
        assert await generate_report(session, uuid.UUID(report["id"])) == "completed"
    status = await stack.client.get(
        f"/api/v1/projects/{project}/reports/{report['id']}", headers=headers
    )
    result: dict[str, Any] = status.json()
    return result


async def _download(stack: ApiStack, headers: dict[str, str], project: str, report_id: str) -> Any:
    return await stack.client.get(
        f"/api/v1/projects/{project}/reports/{report_id}/download", headers=headers
    )


async def test_json_report_contents_and_integrity(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    job = await _scan(stack, analyst, project, asset)

    report = await _report(stack, analyst, project, format="json")
    assert report["status"] == "completed"
    assert report["schema_version"] == "sentinelx-report/1.0"
    assert report["summary"]["findings"] == 1
    assert stack.report_dispatcher.dispatched == [report["id"]]

    response = await _download(stack, analyst, project, report["id"])
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.headers["content-disposition"].startswith(
        'attachment; filename="sentinelx-report-project-'
    )
    assert response.headers["cache-control"] == "no-store"
    digest = hashlib.sha256(response.content).hexdigest()
    assert response.headers["x-content-sha256"] == digest == report["sha256"]
    assert len(response.content) == report["size_bytes"]

    data = response.json()
    assert data["project"]["name"] == "Acme"
    assert data["scope"]["assets"][0]["value"] == "93.184.215.14"
    authorization = data["scope"]["authorizations"][0]
    assert authorization["reference"] == "SOW-1"
    assert authorization["allow_active"] is True
    assert data["methodology"]["scanners"] == [
        {"scanner": "nmap", "technique": "active", "profiles": ["quick"], "scans": 1}
    ]
    assert data["scans"][0]["id"] == job
    assert data["scans"][0]["finished_at"]
    assert "sentinelx-security" in data["tool_versions"]
    finding = data["findings"][0]
    assert finding["detection"] == "automated"
    assert finding["rule_id"] == "http.cleartext_http"
    assert finding["remediation"]
    assert finding["risk_band"]
    assert INJECTION in finding["evidence"][0]["excerpt"]  # evidence is data, kept verbatim
    assert data["severity_distribution"]["by_severity"]["medium"] == 1
    assert data["remediation_plan"][0]["affected"] == 1
    assert any("automated tools" in item for item in data["limitations"])
    assert data["ai_commentary"] == []
    statement = data["executive_summary"]["statement"]
    assert statement.startswith("As of")
    assert "1 active finding(s) affect 1 asset(s)" in statement

    async with stack.app.state.session_factory() as session:
        actions = [
            r[0]
            for r in await session.execute(
                text(
                    "SELECT action FROM audit_logs WHERE action LIKE 'report.%' ORDER BY created_at"
                )
            )
        ]
    assert actions == ["report.requested", "report.downloaded"]


async def test_pdf_report(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset)
    report = await _report(stack, analyst, project, format="pdf", title="Quarterly assessment")
    response = await _download(stack, analyst, project, report["id"])
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-")
    assert hashlib.sha256(response.content).hexdigest() == report["sha256"]
    assert report["title"] == "Quarterly assessment"


async def test_ai_commentary_only_when_reviewed_and_labelled(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    analysis = (
        await stack.client.post(
            f"/api/v1/projects/{project}/ai/analyses",
            headers=analyst,
            json={"kind": "executive_summary"},
        )
    ).json()
    assert analysis["status"] == "completed"  # deterministic: AI disabled in tests

    first = await _report(stack, analyst, project, format="json")
    data = (await _download(stack, analyst, project, first["id"])).json()
    assert data["ai_commentary"] == []  # not reviewed yet

    await stack.client.post(
        f"/api/v1/projects/{project}/ai/analyses/{analysis['id']}/review", headers=analyst
    )
    second = await _report(stack, analyst, project, format="json")
    data = (await _download(stack, analyst, project, second["id"])).json()
    (comment,) = data["ai_commentary"]
    assert comment["analysis_id"] == analysis["id"]
    assert comment["label"] == "Deterministic summary (no AI model used)"
    assert comment["reviewed_by"] == "analyst@example.com"
    assert comment["prompt_version"] == "executive_summary@1.0.0+system@1.0.0"
    assert any("AI commentary is advisory" in item for item in data["limitations"])

    excluded = await _report(stack, analyst, project, format="json", include_ai=False)
    data = (await _download(stack, analyst, project, excluded["id"])).json()
    assert data["ai_commentary"] == []


async def test_scan_scope_and_resolved_findings(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    first = await _scan(stack, analyst, project, asset)
    second = (await _request(stack, analyst, project, asset)).json()["id"]
    await _run_worker(stack, second)  # finds nothing: the first scan's finding resolves

    project_report = await _report(stack, analyst, project, format="json")
    data = (await _download(stack, analyst, project, project_report["id"])).json()
    assert data["findings"] == []
    assert data["executive_summary"]["active_findings"] == 0

    with_resolved = await _report(stack, analyst, project, format="json", include_resolved=True)
    data = (await _download(stack, analyst, project, with_resolved["id"])).json()
    assert [f["status"] for f in data["findings"]] == ["resolved"]

    scan_report = await _report(
        stack,
        analyst,
        project,
        format="json",
        scope="scan",
        scan_job_id=first,
        include_resolved=True,
    )
    data = (await _download(stack, analyst, project, scan_report["id"])).json()
    assert [s["id"] for s in data["scans"]] == [first]
    assert len(data["findings"]) == 1
    assert data["report"]["scope"] == "scan"

    empty_scan = await _report(
        stack, analyst, project, format="json", scope="scan", scan_job_id=second
    )
    data = (await _download(stack, analyst, project, empty_scan["id"])).json()
    assert data["findings"] == []

    response = await stack.client.post(
        f"/api/v1/projects/{project}/reports", headers=analyst, json={"scope": "scan"}
    )
    assert response.status_code == 422
    response = await stack.client.post(
        f"/api/v1/projects/{project}/reports",
        headers=analyst,
        json={"scope": "scan", "scan_job_id": str(uuid.uuid4())},
    )
    assert response.status_code == 404


async def test_permissions_isolation_and_lifecycle(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    viewer = await stack.create_user("viewer@example.com", role=RoleName.VIEWER)
    await stack.client.post(
        f"/api/v1/projects/{project}/members", headers=admin, json={"user_id": str(viewer.id)}
    )
    viewer_headers = await stack.login(viewer.email)
    base = f"/api/v1/projects/{project}/reports"
    assert (await stack.client.post(base, headers=viewer_headers, json={})).status_code == 403

    report = await _report(stack, analyst, project, format="pdf")
    # Viewers read and download reports.
    assert (await stack.client.get(base, headers=viewer_headers)).json()["total"] == 1
    assert (await _download(stack, viewer_headers, project, report["id"])).status_code == 200

    other = (
        await stack.client.post("/api/v1/projects", headers=admin, json={"name": "Other"})
    ).json()["id"]
    response = await stack.client.get(
        f"/api/v1/projects/{other}/reports/{report['id']}/download", headers=admin
    )
    assert response.status_code == 404

    # Not ready yet → 409; queue down → failed; stale → failed.
    pending = (await stack.client.post(base, headers=analyst, json={"format": "json"})).json()
    assert (await _download(stack, analyst, project, pending["id"])).status_code == 409
    stack.report_dispatcher.fail = True
    failed = (await stack.client.post(base, headers=analyst, json={"format": "json"})).json()
    assert failed["status"] == "failed"
    assert "queue is unavailable" in failed["error"]
    async with stack.app.state.session_factory() as session:
        await session.execute(
            text("UPDATE reports SET created_at = :t WHERE id = :id"),
            {"t": datetime.now(UTC) - timedelta(hours=1), "id": pending["id"]},
        )
        await session.commit()
    stale = (await stack.client.get(f"{base}/{pending['id']}", headers=analyst)).json()
    assert stale["status"] == "failed"

    # A finished report is never regenerated.
    async with stack.app.state.session_factory() as session:
        assert await generate_report(session, uuid.UUID(report["id"])) is None

    assert (
        await stack.client.delete(f"{base}/{report['id']}", headers=viewer_headers)
    ).status_code == 403
    assert (await stack.client.delete(f"{base}/{report['id']}", headers=analyst)).status_code == 204
    assert (await stack.client.get(f"{base}/{report['id']}", headers=analyst)).status_code == 404
    listing = (await stack.client.get(base, headers=analyst)).json()
    assert all("content" not in item for item in listing["items"])
    assert json.dumps(listing)  # serializable without the binary column
