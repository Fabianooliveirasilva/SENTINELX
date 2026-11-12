"""Monitoring: event timeline, alert rules, notification delivery and scheduled scans."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta
from typing import Any, ClassVar

import httpx
import pytest
from sqlalchemy import select, text, update

from app.core.permissions import RoleName
from app.models import Notification, ScanSchedule, SecurityEvent
from app.services.intel import apply_kev
from app.services.notifications import Deliverer, WebhookClient, deliver_due
from app.services.schedules import run_due
from sentinelx_security.intel.nvd import KevCatalog, KevEntry
from sentinelx_security.scanners import Observation, RawOutput, ScanContext, ScanError, Scanner
from sentinelx_security.scanners.base import ScannerName
from sentinelx_security.scope import AssetType, NetworkPolicy, StaticResolver, Technique
from tests.integration.conftest import ApiStack
from tests.integration.test_findings import _scan
from tests.integration.test_scans import _asset, _request, _run_worker, _setup

pytestmark = pytest.mark.integration


class BrokenScanner(Scanner):
    name: ClassVar[ScannerName] = ScannerName.NMAP
    technique: ClassVar[Technique] = Technique.ACTIVE
    description: ClassVar[str] = "fails"
    profiles: ClassVar[Mapping[str, str]] = {"quick": "q"}
    default_profile: ClassVar[str] = "quick"
    supported_asset_types = frozenset({AssetType.IP_ADDRESS})

    async def execute(self, ctx: ScanContext) -> RawOutput:
        raise ScanError("tool_crashed", "The tool crashed.")

    def normalize_results(self, raw: RawOutput) -> list[Observation]:
        return []


async def _events(stack: ApiStack, headers: dict[str, str], project: str, **params: Any) -> Any:
    response = await stack.client.get(
        f"/api/v1/projects/{project}/events", headers=headers, params=params
    )
    assert response.status_code == 200, response.text
    return response.json()


async def _channel(
    stack: ApiStack, headers: dict[str, str], project: str, **body: Any
) -> dict[str, Any]:
    payload = {"name": "SecOps mail", "kind": "email", "recipients": ["soc@example.com"], **body}
    response = await stack.client.post(
        f"/api/v1/projects/{project}/notification-channels", headers=headers, json=payload
    )
    assert response.status_code == 201, response.text
    channel: dict[str, Any] = response.json()
    return channel


async def _rule(
    stack: ApiStack, headers: dict[str, str], project: str, channel: str, **body: Any
) -> dict[str, Any]:
    payload = {"name": "Important", "channel_ids": [channel], **body}
    response = await stack.client.post(
        f"/api/v1/projects/{project}/alert-rules", headers=headers, json=payload
    )
    assert response.status_code == 201, response.text
    rule: dict[str, Any] = response.json()
    return rule


async def _notifications(stack: ApiStack) -> list[Notification]:
    async with stack.app.state.session_factory() as session:
        return list(
            (await session.execute(select(Notification).order_by(Notification.created_at)))
            .scalars()
            .all()
        )


def _deliverer(
    stack: ApiStack,
    handler: Any = None,
    dns: Mapping[str, list[str]] | None = None,
) -> Deliverer:
    transport = httpx.MockTransport(handler or (lambda _r: httpx.Response(204)))
    webhooks = WebhookClient(
        StaticResolver(dns or {"hooks.example.com": ["93.184.215.14"]}),
        NetworkPolicy(),
        timeout_seconds=2,
        transport=transport,
    )
    return Deliverer(stack.settings, stack.email, webhooks)


async def _deliver(stack: ApiStack, deliverer: Deliverer) -> dict[str, int]:
    async with stack.app.state.session_factory() as session:
        return await deliver_due(session, deliverer, stack.settings)


async def _make_due(stack: ApiStack) -> None:
    async with stack.app.state.session_factory() as session:
        await session.execute(
            update(Notification)
            .where(Notification.status == "pending")
            .values(next_attempt_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        await session.commit()


# --------------------------------------------------------------------- timeline


async def test_scans_and_findings_populate_the_timeline(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    viewer = await stack.create_user("viewer@example.com", role=RoleName.VIEWER)
    await stack.client.post(
        f"/api/v1/projects/{project}/members", headers=admin, json={"user_id": str(viewer.id)}
    )
    viewer_headers = await stack.login(viewer.email)
    asset = await _asset(stack, analyst, project)
    job = await _scan(stack, analyst, project, asset, "cleartext_http", "missing_csp")

    page = await _events(stack, viewer_headers, project)
    types = [e["event_type"] for e in page["items"]]
    assert types.count("finding.created") == 2
    assert "scan.completed" in types
    assert "asset.created" in types
    assert "authorization.granted" in types
    completed = next(e for e in page["items"] if e["event_type"] == "scan.completed")
    assert completed["scan_job_id"] == job
    assert completed["details"]["findings"]["new"] == 2

    # Filters: severity floor, type and asset.
    medium = await _events(stack, viewer_headers, project, min_severity="medium")
    assert {e["severity"] for e in medium["items"]} <= {"medium", "high", "critical"}
    assert [e["details"]["rule_id"] for e in medium["items"]] == ["http.cleartext_http"]
    only = await _events(stack, viewer_headers, project, event_type="scan.completed")
    assert only["total"] == 1
    by_asset = await _events(stack, viewer_headers, project, asset_id=asset)
    assert by_asset["total"] == page["total"]
    future = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    assert (await _events(stack, viewer_headers, project, since=future))["total"] == 0

    # A re-scan without the CSP issue resolves it and does not re-announce the other.
    await _scan(stack, analyst, project, asset, "cleartext_http")
    page = await _events(stack, viewer_headers, project)
    types = [e["event_type"] for e in page["items"]]
    assert types.count("finding.created") == 2
    assert types.count("finding.resolved") == 1

    summary = (
        await stack.client.get(f"/api/v1/projects/{project}/events/summary", headers=viewer_headers)
    ).json()
    assert summary["total"] == page["total"]
    catalog = (await stack.client.get("/api/v1/events/types", headers=viewer_headers)).json()
    assert "finding.kev_listed" in {c["type"] for c in catalog}
    assert "notification.test" not in {c["type"] for c in catalog}


async def test_timeline_is_project_isolated(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    other = (
        await stack.client.post("/api/v1/projects", headers=admin, json={"name": "Other"})
    ).json()["id"]
    await _asset(stack, analyst, project)
    response = await stack.client.get(f"/api/v1/projects/{other}/events", headers=analyst)
    assert response.status_code == 404
    for path in ("notification-channels", "alert-rules", "scan-schedules"):
        response = await stack.client.get(f"/api/v1/projects/{other}/{path}", headers=analyst)
        assert response.status_code == 404, path


async def test_failed_scans_triage_and_emergency_stop_are_events(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    job = (await _request(stack, analyst, project, asset)).json()
    assert await _run_worker(stack, job["id"], BrokenScanner()) == "failed"

    job_id = await _scan(stack, analyst, project, asset, "cleartext_http")
    finding = (
        await stack.client.get(f"/api/v1/projects/{project}/findings", headers=analyst)
    ).json()["items"][0]
    response = await stack.client.post(
        f"/api/v1/projects/{project}/findings/{finding['id']}/status",
        headers=analyst,
        json={"status": "accepted_risk", "reason": "Compensating control in place"},
    )
    assert response.status_code == 200, response.text

    response = await stack.client.post(
        "/api/v1/scans/emergency-stop", headers=admin, json={"reason": "Incident drill"}
    )
    assert response.status_code == 200, response.text

    page = await _events(stack, analyst, project)
    by_type = {e["event_type"]: e for e in page["items"]}
    assert by_type["scan.failed"]["severity"] == "medium"
    assert by_type["scan.failed"]["details"]["error_code"] == "tool_crashed"
    assert by_type["finding.status_changed"]["actor_email"] == "analyst@example.com"
    assert by_type["finding.status_changed"]["details"]["to"] == "accepted_risk"
    assert by_type["scanning.halted"]["severity"] == "high"
    assert by_type["scanning.halted"]["details"]["reason"] == "Incident drill"
    assert job_id


async def test_kev_listing_emits_an_event_once(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset, "cleartext_http")
    async with stack.app.state.session_factory() as session:
        await session.execute(
            text(
                "INSERT INTO cves (id, description, published_at, last_modified_at, "
                "\"references\", cwes, source) VALUES ('CVE-2099-0001', 'x', now(), now(), "
                "'{}', '{}', 'nvd')"
            )
        )
        await session.execute(text("UPDATE findings SET cve_id = 'CVE-2099-0001'"))
        await session.commit()
    catalog = KevCatalog(
        version="2099.01.01",
        entries={
            "CVE-2099-0001": KevEntry(
                cve_id="CVE-2099-0001",
                date_added=date(2099, 1, 1),
                due_date=date(2099, 1, 22),
                ransomware="Known",
                name="Test",
            )
        },
    )
    for _ in range(2):  # the second sync must not announce it again
        async with stack.app.state.session_factory() as session:
            await apply_kev(session, catalog)
            await session.commit()
    events = (await _events(stack, analyst, project, event_type="finding.kev_listed"))["items"]
    assert len(events) == 1
    assert events[0]["severity"] == "critical"
    assert events[0]["details"]["cve_id"] == "CVE-2099-0001"


async def test_risk_band_changes_are_events(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _scan(stack, analyst, project, asset, "cleartext_http")
    before = (
        await stack.client.get(f"/api/v1/projects/{project}/findings", headers=analyst)
    ).json()["items"][0]["risk_band"]
    response = await stack.client.patch(
        f"/api/v1/projects/{project}/assets/{asset}",
        headers=analyst,
        json={"criticality": "low", "exposure": "internal"},
    )
    assert response.status_code == 200, response.text
    after = (
        await stack.client.get(f"/api/v1/projects/{project}/findings", headers=analyst)
    ).json()["items"][0]["risk_band"]
    assert before != after  # the fixture finding is chosen to cross a band boundary
    events = (await _events(stack, analyst, project, event_type="finding.risk_band_changed"))[
        "items"
    ]
    assert len(events) == 1
    assert events[0]["details"]["from"] == before
    assert events[0]["details"]["to"] == after
    assert events[0]["severity"] == after


# --------------------------------------------------------------------- channels and rules


async def test_alert_configuration_permissions(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    viewer = await stack.create_user("viewer@example.com", role=RoleName.VIEWER)
    await stack.client.post(
        f"/api/v1/projects/{project}/members", headers=admin, json={"user_id": str(viewer.id)}
    )
    viewer_headers = await stack.login(viewer.email)
    base = f"/api/v1/projects/{project}"
    body = {"name": "x", "kind": "email", "recipients": ["a@example.com"]}
    assert (
        await stack.client.post(f"{base}/notification-channels", headers=viewer_headers, json=body)
    ).status_code == 403
    assert (
        await stack.client.get(f"{base}/notification-channels", headers=viewer_headers)
    ).status_code == 403
    assert (
        await stack.client.get(f"{base}/notifications", headers=viewer_headers)
    ).status_code == 403
    # Viewers can see which rules exist, not where they deliver.
    assert (
        await stack.client.get(f"{base}/alert-rules", headers=viewer_headers)
    ).status_code == 200

    channel = await _channel(stack, analyst, project)
    assert channel["signing_secret"] is None
    rule_body = {"name": "r", "channel_ids": [channel["id"]]}
    assert (
        await stack.client.post(f"{base}/alert-rules", headers=viewer_headers, json=rule_body)
    ).status_code == 403
    await _rule(stack, analyst, project, channel["id"])


async def test_channel_validation_and_secret_handling(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    base = f"/api/v1/projects/{project}/notification-channels"
    for url, expected in (
        ("ftp://hooks.example.com/x", 422),
        ("https://user:pass@hooks.example.com/x", 422),
        ("https://hooks.example.com/x#frag", 422),
        ("https:///nohost", 422),
    ):
        response = await stack.client.post(
            base, headers=analyst, json={"name": url[:30], "kind": "webhook", "url": url}
        )
        assert response.status_code == expected, (url, response.text)
    response = await stack.client.post(
        base, headers=analyst, json={"name": "nobody", "kind": "email", "recipients": []}
    )
    assert response.status_code == 422

    hook = await _channel(
        stack,
        analyst,
        project,
        name="Chat",
        kind="webhook",
        url="https://hooks.example.com/in/T0K3N",
    )
    secret = hook["signing_secret"]
    assert secret.startswith("whsec_")
    assert hook["has_secret"] is True
    listed = (await stack.client.get(base, headers=analyst)).json()
    assert all("signing_secret" not in c for c in listed)
    async with stack.app.state.session_factory() as session:
        stored = (
            await session.execute(text("SELECT secret_encrypted FROM notification_channels"))
        ).scalar_one()
        audit = json.dumps(
            [
                r[0]
                for r in await session.execute(
                    text("SELECT details FROM audit_logs WHERE action LIKE 'notification_channel%'")
                )
            ]
        )
    assert secret not in stored
    assert "T0K3N" not in audit
    assert secret not in audit

    rotated = (
        await stack.client.post(f"{base}/{hook['id']}/rotate-secret", headers=analyst)
    ).json()
    assert rotated["signing_secret"] != secret
    duplicate = await stack.client.post(
        base,
        headers=analyst,
        json={"name": "Chat", "kind": "email", "recipients": ["a@example.com"]},
    )
    assert duplicate.status_code == 409

    rules = f"/api/v1/projects/{project}/alert-rules"
    bad = await stack.client.post(
        rules,
        headers=analyst,
        json={"name": "r", "channel_ids": [hook["id"]], "event_types": ["finding.exploded"]},
    )
    assert bad.status_code == 422
    missing = await stack.client.post(
        rules, headers=analyst, json={"name": "r", "channel_ids": [str(uuid.uuid4())]}
    )
    assert missing.status_code == 404


async def test_rules_match_severity_type_and_quiet_period(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    channel = await _channel(stack, analyst, project)
    await _rule(
        stack,
        analyst,
        project,
        channel["id"],
        name="New medium+ findings",
        event_types=["finding.created"],
        min_severity="medium",
    )
    await _rule(
        stack,
        analyst,
        project,
        channel["id"],
        name="Scan failures",
        event_types=["scan.failed"],
        min_severity="info",
        quiet_period_minutes=60,
    )
    await _scan(stack, analyst, project, asset, "cleartext_http", "missing_csp")
    for _ in range(2):
        job = (await _request(stack, analyst, project, asset)).json()
        assert await _run_worker(stack, job["id"], BrokenScanner()) == "failed"

    rows = await _notifications(stack)
    assert [n.status for n in rows] == ["pending", "pending", "suppressed"]
    async with stack.app.state.session_factory() as session:
        events = {
            e.id: e.event_type for e in (await session.execute(select(SecurityEvent))).scalars()
        }
        types = [events[n.event_id] for n in rows]
    assert types == ["finding.created", "scan.failed", "scan.failed"]

    result = await _deliver(stack, _deliverer(stack))
    assert result == {"sent": 2, "retrying": 0, "failed": 0}
    assert len(stack.email.outbox) == 2
    message = stack.email.outbox[0]
    assert message.to == "soc@example.com"
    assert message.subject.startswith("[SentinelX] MEDIUM:")
    assert f"/projects/{project}/events" in message.body

    log = (
        await stack.client.get(f"/api/v1/projects/{project}/notifications", headers=analyst)
    ).json()
    assert log["total"] == 3
    assert {n["status"] for n in log["items"]} == {"sent", "suppressed"}


# --------------------------------------------------------------------- delivery


async def test_webhook_delivery_is_signed_and_pinned(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    hook = await _channel(
        stack, analyst, project, name="Hook", kind="webhook", url="https://hooks.example.com/in"
    )
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    response = await stack.client.post(
        f"/api/v1/projects/{project}/notification-channels/{hook['id']}/test", headers=analyst
    )
    assert response.status_code == 202, response.text
    assert await _deliver(stack, _deliverer(stack, handler)) == {
        "sent": 1,
        "retrying": 0,
        "failed": 0,
    }
    request = seen[0]
    assert request.url.host == "93.184.215.14"  # the pinned, policy-checked address
    assert request.headers["host"] == "hooks.example.com"
    assert request.extensions["sni_hostname"] == "hooks.example.com"
    assert request.headers["x-sentinelx-event"] == "notification.test"
    timestamp, signature = (
        p.split("=", 1)[1] for p in request.headers["x-sentinelx-signature"].split(",")
    )
    expected = hmac.new(
        hook["signing_secret"].encode(), f"{timestamp}.".encode() + request.content, hashlib.sha256
    ).hexdigest()
    assert hmac.compare_digest(signature, expected)
    body = json.loads(request.content)
    assert body["event"]["type"] == "notification.test"
    assert body["delivery_id"] == response.json()["notification_id"]


async def test_webhook_refuses_internal_destinations(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    base = f"/api/v1/projects/{project}/notification-channels"
    targets = {
        "internal.example.com": ["10.0.0.5"],
        "rebind.example.com": ["93.184.215.14", "127.0.0.1"],
        "metadata.example.com": ["169.254.169.254"],
    }
    for host in targets:
        hook = await _channel(
            stack, analyst, project, name=host, kind="webhook", url=f"https://{host}/x"
        )
        await stack.client.post(f"{base}/{hook['id']}/test", headers=analyst)
    literal = await _channel(
        stack, analyst, project, name="literal", kind="webhook", url="http://127.0.0.1:8000/x"
    )
    await stack.client.post(f"{base}/{literal['id']}/test", headers=analyst)

    calls: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    result = await _deliver(stack, _deliverer(stack, record, targets))
    assert result == {"sent": 0, "retrying": 0, "failed": 4}
    assert calls == []
    for n in await _notifications(stack):
        assert n.status == "failed"
        assert n.last_error is not None
        assert "refused by policy" in n.last_error


async def test_failed_deliveries_retry_with_backoff_then_give_up(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    hook = await _channel(
        stack, analyst, project, name="Hook", kind="webhook", url="https://hooks.example.com/in"
    )
    await stack.client.post(
        f"/api/v1/projects/{project}/notification-channels/{hook['id']}/test", headers=analyst
    )
    failing = _deliverer(stack, lambda _r: httpx.Response(503))
    assert await _deliver(stack, failing) == {"sent": 0, "retrying": 1, "failed": 0}
    (row,) = await _notifications(stack)
    assert row.status == "pending"
    assert row.attempts == 1
    assert row.response_status == 503
    assert row.next_attempt_at > datetime.now(UTC)
    # Not due yet: nothing is sent.
    assert await _deliver(stack, failing) == {"sent": 0, "retrying": 0, "failed": 0}
    for _ in range(stack.settings.notification_max_attempts - 1):
        await _make_due(stack)
        await _deliver(stack, failing)
    (row,) = await _notifications(stack)
    assert row.status == "failed"
    assert row.attempts == stack.settings.notification_max_attempts
    assert row.last_error == "The endpoint answered HTTP 503."

    # Client errors other than 408/429 are permanent.
    await stack.client.post(
        f"/api/v1/projects/{project}/notification-channels/{hook['id']}/test", headers=analyst
    )
    assert await _deliver(stack, _deliverer(stack, lambda _r: httpx.Response(404))) == {
        "sent": 0,
        "retrying": 0,
        "failed": 1,
    }


async def test_disabled_channels_are_not_used(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    channel = await _channel(stack, analyst, project)
    await _rule(stack, analyst, project, channel["id"], min_severity="info")
    response = await stack.client.patch(
        f"/api/v1/projects/{project}/notification-channels/{channel['id']}",
        headers=analyst,
        json={"enabled": False},
    )
    assert response.status_code == 200
    assert response.json()["enabled"] is False
    await _scan(stack, analyst, project, asset, "cleartext_http")
    assert await _notifications(stack) == []
    response = await stack.client.post(
        f"/api/v1/projects/{project}/notification-channels/{channel['id']}/test", headers=analyst
    )
    assert response.status_code == 409


# --------------------------------------------------------------------- schedules


async def _run_schedules(stack: ApiStack) -> dict[str, int]:
    async with stack.app.state.session_factory() as session:
        return await run_due(
            session, stack.app.state.scope_engine, stack.settings, stack.dispatcher
        )


async def test_schedules_start_scans_with_owner_authority(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    base = f"/api/v1/projects/{project}/scan-schedules"
    viewer = await stack.user_headers("viewer@example.com")
    assert (
        await stack.client.post(
            base, headers=viewer, json={"asset_id": asset, "scanner": "nmap", "interval_hours": 24}
        )
    ).status_code in (403, 404)
    bad = await stack.client.post(
        base,
        headers=analyst,
        json={"asset_id": asset, "scanner": "nmap", "profile": "insane", "interval_hours": 24},
    )
    assert bad.status_code == 422
    schedule = (
        await stack.client.post(
            base, headers=analyst, json={"asset_id": asset, "scanner": "nmap", "interval_hours": 24}
        )
    ).json()
    assert schedule["profile"] == "quick"
    assert schedule["enabled"] is True

    assert await _run_schedules(stack) == {"started": 1, "skipped": 0}
    assert len(stack.dispatcher.dispatched) == 1
    current = (await stack.client.get(base, headers=analyst)).json()["items"][0]
    assert current["last_status"] == "started"
    assert current["last_scan_job_id"] == stack.dispatcher.dispatched[0]
    next_run = datetime.fromisoformat(current["next_run_at"])
    assert next_run > datetime.now(UTC) + timedelta(hours=23)
    # Not due again until the next slot.
    assert await _run_schedules(stack) == {"started": 0, "skipped": 0}

    scan = (
        await stack.client.get(
            f"/api/v1/projects/{project}/scans/{current['last_scan_job_id']}", headers=analyst
        )
    ).json()
    assert scan["requested_by_id"] == str(stack.users["analyst@example.com"].id)

    response = await stack.client.patch(
        f"{base}/{schedule['id']}", headers=analyst, json={"enabled": False}
    )
    assert response.json()["enabled"] is False
    assert (
        await stack.client.delete(f"{base}/{schedule['id']}", headers=analyst)
    ).status_code == 204
    assert admin


async def test_schedules_skip_when_controls_forbid_the_scan(stack: ApiStack) -> None:
    admin, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    base = f"/api/v1/projects/{project}/scan-schedules"
    schedule = (
        await stack.client.post(
            base, headers=analyst, json={"asset_id": asset, "scanner": "nmap", "interval_hours": 1}
        )
    ).json()

    async def make_due() -> None:
        async with stack.app.state.session_factory() as session:
            await session.execute(
                update(ScanSchedule).values(next_run_at=datetime.now(UTC) - timedelta(minutes=1))
            )
            await session.commit()

    # 1. Emergency stop.
    await stack.client.post("/api/v1/scans/emergency-stop", headers=admin, json={"reason": "drill"})
    assert await _run_schedules(stack) == {"started": 0, "skipped": 1}
    current = (await stack.client.get(base, headers=analyst)).json()["items"][0]
    assert current["last_status"] == "skipped"
    assert "emergency stop" in current["last_message"]
    await stack.client.post("/api/v1/scans/resume", headers=admin)

    # 2. The owner lost access to the project.
    await make_due()
    analyst_id = stack.users["analyst@example.com"].id
    response = await stack.client.delete(
        f"/api/v1/projects/{project}/members/{analyst_id}", headers=admin
    )
    assert response.status_code == 204, response.text
    assert await _run_schedules(stack) == {"started": 0, "skipped": 1}
    current = (await stack.client.get(base, headers=admin)).json()["items"][0]
    assert current["last_message"] == "Project not found."

    # 3. The owner's account was deactivated.
    await make_due()
    async with stack.app.state.session_factory() as session:
        await session.execute(
            text("UPDATE users SET is_active = false WHERE id = :id"), {"id": analyst_id}
        )
        await session.commit()
    assert await _run_schedules(stack) == {"started": 0, "skipped": 1}
    current = (await stack.client.get(base, headers=admin)).json()["items"][0]
    assert "no longer has an active account" in current["last_message"]

    skipped = (await _events(stack, admin, project, event_type="schedule.skipped"))["items"]
    assert len(skipped) == 3
    assert {e["details"]["schedule_id"] for e in skipped} == {schedule["id"]}
    assert stack.dispatcher.dispatched == []


async def test_rule_and_channel_lifecycle_is_audited(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    first = await _channel(stack, analyst, project)
    second = await _channel(stack, analyst, project, name="Backup", recipients=["b@example.com"])
    rule = await _rule(stack, analyst, project, first["id"])
    rules = f"/api/v1/projects/{project}/alert-rules"
    channels = f"/api/v1/projects/{project}/notification-channels"

    response = await stack.client.patch(
        f"{rules}/{rule['id']}",
        headers=analyst,
        json={
            "name": "Renamed",
            "event_types": ["scan.failed", "finding.created"],
            "min_severity": "critical",
            "asset_id": asset,
            "quiet_period_minutes": 0,
            "channel_ids": [second["id"]],
            "enabled": False,
        },
    )
    assert response.status_code == 200, response.text
    updated = response.json()
    assert updated["name"] == "Renamed"
    assert updated["event_types"] == ["finding.created", "scan.failed"]
    assert updated["asset_id"] == asset
    assert [c["name"] for c in updated["channels"]] == ["Backup"]
    assert updated["enabled"] is False
    other_asset = await stack.client.patch(
        f"{rules}/{rule['id']}", headers=analyst, json={"asset_id": str(uuid.uuid4())}
    )
    assert other_asset.status_code == 404
    clash = await _rule(stack, analyst, project, first["id"], name="Other")
    rename = await stack.client.patch(
        f"{rules}/{clash['id']}", headers=analyst, json={"name": "Renamed"}
    )
    assert rename.status_code == 409

    response = await stack.client.patch(
        f"{channels}/{first['id']}",
        headers=analyst,
        json={"name": "Primary", "recipients": ["NEW@example.com", "new@example.com"]},
    )
    assert response.status_code == 200, response.text
    assert response.json()["recipients"] == ["new@example.com"]
    not_webhook = await stack.client.post(
        f"{channels}/{first['id']}/rotate-secret", headers=analyst
    )
    assert not_webhook.status_code == 422

    assert (await stack.client.delete(f"{rules}/{rule['id']}", headers=analyst)).status_code == 204
    assert (
        await stack.client.delete(f"{channels}/{second['id']}", headers=analyst)
    ).status_code == 204
    assert (await stack.client.get(f"{rules}/{rule['id']}", headers=analyst)).status_code in (
        404,
        405,
    )
    remaining = (await stack.client.get(channels, headers=analyst)).json()
    assert [c["name"] for c in remaining] == ["Primary"]

    async with stack.app.state.session_factory() as session:
        actions = {
            r[0]
            for r in await session.execute(
                text(
                    "SELECT action FROM audit_logs WHERE action LIKE 'alert_rule.%' "
                    "OR action LIKE 'notification_channel.%'"
                )
            )
        }
    assert {
        "alert_rule.created",
        "alert_rule.updated",
        "alert_rule.deleted",
        "notification_channel.created",
        "notification_channel.updated",
        "notification_channel.deleted",
    } <= actions


async def test_schedule_updates(stack: ApiStack) -> None:
    _, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    base = f"/api/v1/projects/{project}/scan-schedules"
    schedule = (
        await stack.client.post(
            base, headers=analyst, json={"asset_id": asset, "scanner": "nmap", "interval_hours": 24}
        )
    ).json()
    later = (datetime.now(UTC) + timedelta(days=2)).isoformat()
    response = await stack.client.patch(
        f"{base}/{schedule['id']}",
        headers=analyst,
        json={"interval_hours": 168, "next_run_at": later, "profile": "quick"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["interval_hours"] == 168
    assert response.json()["next_run_at"].startswith(later[:16])
    bad = await stack.client.patch(
        f"{base}/{schedule['id']}", headers=analyst, json={"profile": "x"}
    )
    assert bad.status_code == 422
    missing = await stack.client.patch(
        f"{base}/{uuid.uuid4()}", headers=analyst, json={"enabled": False}
    )
    assert missing.status_code == 404
    unknown_asset = await stack.client.post(
        base,
        headers=analyst,
        json={"asset_id": str(uuid.uuid4()), "scanner": "nmap", "interval_hours": 24},
    )
    assert unknown_asset.status_code == 404
