"""Scan pipeline wiring: queues, chain shape, sandbox isolation and execution."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any, ClassVar

import pytest
from celery import Celery
from celery.canvas import _chain

from app.core.config import Settings
from app.services.scan_dispatch import (
    EXECUTE_TASK,
    ORCHESTRATOR_QUEUE,
    RECORD_TASK,
    SCANNER_QUEUE,
    START_TASK,
    ZAP_QUEUE,
    CeleryScanDispatcher,
)
from sentinelx_security.scanners import (
    Observation,
    RawOutput,
    ScanContext,
    Scanner,
    ScannerName,
    ScanRequest,
)
from sentinelx_security.scope import AssetType, Technique
from sentinelx_workers.celery_app import celery_app
from sentinelx_workers.scanner_app import ScannerSettings, scanner_app
from sentinelx_workers.tasks import scanner as scanner_tasks


def test_orchestrator_and_sandbox_register_disjoint_tasks() -> None:
    # Imports the modules listed in each app's ``include`` (as a worker would).
    celery_app.loader.import_default_modules()
    scanner_app.loader.import_default_modules()
    assert {START_TASK, RECORD_TASK, "sentinelx.scans.expire_stale"} <= set(celery_app.tasks)
    assert EXECUTE_TASK not in celery_app.tasks
    assert EXECUTE_TASK in scanner_app.tasks
    assert START_TASK not in scanner_app.tasks


def test_sandbox_configuration_is_isolated() -> None:
    conf = scanner_app.conf
    assert list(conf.accept_content) == ["json"]
    assert conf.task_default_queue == SCANNER_QUEUE
    assert conf.worker_max_tasks_per_child == 1
    assert conf.task_ignore_result is True
    # The sandbox settings model has no database URL or signing secret at all.
    assert "database_url" not in ScannerSettings.model_fields
    assert "secret_key" not in ScannerSettings.model_fields


def test_beat_expires_stale_jobs() -> None:
    entry = celery_app.conf.beat_schedule["expire-stale-scan-jobs"]
    assert entry["task"] == "sentinelx.scans.expire_stale"
    assert entry["options"]["queue"] == ORCHESTRATOR_QUEUE


def test_dispatcher_publishes_a_three_step_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    app = Celery("test", broker="memory://")
    sent: list[dict[str, Any]] = []

    original = _chain.apply_async

    def recording_apply_async(self: _chain, *args: Any, **kwargs: Any) -> Any:
        sent.extend(
            {"name": t.task, "args": t.args, "options": dict(t.options)} for t in self.tasks
        )
        return original(self, *args, **kwargs)

    monkeypatch.setattr(_chain, "apply_async", recording_apply_async)
    handle = CeleryScanDispatcher(app).dispatch("job-1", "nmap", timeout_seconds=100)

    assert [s["name"] for s in sent] == [START_TASK, EXECUTE_TASK, RECORD_TASK]
    assert [s["options"]["queue"] for s in sent] == [
        ORCHESTRATOR_QUEUE,
        SCANNER_QUEUE,
        ORCHESTRATOR_QUEUE,
    ]
    assert sent[0]["args"] == ("job-1",)
    assert sent[1]["options"]["time_limit"] == 160
    assert handle.execute_task_id

    sent.clear()
    CeleryScanDispatcher(app).dispatch("job-2", "zap", timeout_seconds=900)
    assert sent[1]["options"]["queue"] == ZAP_QUEUE


class EchoScanner(Scanner):
    name: ClassVar[ScannerName] = ScannerName.NMAP
    technique: ClassVar[Technique] = Technique.ACTIVE
    description: ClassVar[str] = "echo"
    profiles: ClassVar[Mapping[str, str]] = {"quick": "q"}
    default_profile: ClassVar[str] = "quick"
    supported_asset_types = frozenset({AssetType.IP_ADDRESS})

    async def execute(self, ctx: ScanContext) -> RawOutput:
        return RawOutput(data=[a.compressed for a in ctx.pinned_addresses])

    def normalize_results(self, raw: RawOutput) -> list[Observation]:
        return [Observation("open_port", a, {}) for a in raw.data]


def _request(target: str) -> dict[str, Any]:
    return ScanRequest(
        job_id="job-1",
        scanner=ScannerName.NMAP,
        profile="quick",
        target=target,
        assets=[
            {
                "id": "6f1c3a52-1b77-4c43-9a51-3b6c2b1d2f10",
                "type": "ip_address",
                "value": "93.184.215.14",
                "active": True,
                "authorizations": [
                    {
                        "id": "1b0d9f3e-35a4-4d55-8b0f-2a6a3d8b9e11",
                        "valid_from": "2020-01-01T00:00:00+00:00",
                        "valid_until": "2999-01-01T00:00:00+00:00",
                        "revoked": False,
                        "allow_active": True,
                        "allow_intrusive": False,
                        "include_subdomains": False,
                        "ip_ranges": ["93.184.215.0/24"],
                    }
                ],
            }
        ],
        timeout_seconds=10,
    ).to_dict()


def test_execute_task_skips_jobs_the_orchestrator_dropped() -> None:
    assert scanner_tasks.execute.run(None) is None


def test_execute_task_rechecks_scope_and_pins_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        scanner_tasks, "build_scanners", lambda _config: {ScannerName.NMAP: EchoScanner()}
    )
    allowed = scanner_tasks.execute.run(_request("93.184.215.14"))
    assert allowed["status"] == "completed"
    assert allowed["observations"][0]["key"] == "93.184.215.14"

    # A target outside the snapshot's scope is denied inside the sandbox too.
    denied = scanner_tasks.execute.run(_request("198.51.100.7"))
    assert denied["status"] == "denied"
    assert denied["observations"] == []
    for blocked in ("127.0.0.1", "169.254.169.254"):
        assert scanner_tasks.execute.run(_request(blocked))["status"] == "denied"
    assert ipaddress.ip_address("93.184.215.14").is_global


def test_scanner_settings_require_a_broker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINELX_REDIS_URL", raising=False)
    monkeypatch.delenv("SENTINELX_CELERY_BROKER_URL", raising=False)
    with pytest.raises(ValueError, match="BROKER_URL"):
        _ = ScannerSettings().broker_url
    assert Settings.model_fields["database_url"].is_required()
