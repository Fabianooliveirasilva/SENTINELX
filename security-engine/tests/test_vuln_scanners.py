"""Nuclei and ZAP adapters: safe invocation, egress enforcement, parsing, mapping."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx
import pytest

from sentinelx_security.findings import Confidence, Severity, derive_findings
from sentinelx_security.scanners import ScanContext, ScanError
from sentinelx_security.scanners.nmap import ProcessResult
from sentinelx_security.scanners.nuclei import (
    EXCLUDED_TAGS,
    FORBIDDEN_FLAGS,
    NucleiScanner,
    build_argv,
    parse_jsonl,
)
from sentinelx_security.scanners.zap import ZapScanner, aggregate_alerts, include_regex
from sentinelx_security.scope import AssetType, Technique, parse_target

FIXTURES = Path(__file__).parent / "fixtures"
PINNED = ipaddress.ip_address("93.184.215.14")


def ctx(target: str, profile: str, timeout: float = 120.0) -> ScanContext:
    return ScanContext(
        target=parse_target(target),
        pinned_addresses=(PINNED,),
        profile=profile,
        timeout_seconds=timeout,
    )


# ----------------------------------------------------------------------------- nuclei


def test_nuclei_argv_is_curated() -> None:
    argv = build_argv("nuclei", "baseline", "https://app.example.com/", "http://127.0.0.1:9", "/t")
    flags = {a for a in argv if a.startswith("-")}
    assert not flags & FORBIDDEN_FLAGS
    assert {"-no-interactsh", "-disable-update-check", "-omit-raw"} <= flags
    assert argv[argv.index("-proxy") + 1] == "http://127.0.0.1:9"
    assert argv[argv.index("-protocol-type") + 1] == "http"
    assert set(argv[argv.index("-exclude-tags") + 1].split(",")) == set(EXCLUDED_TAGS)
    templates = [argv[i + 1] for i, a in enumerate(argv) if a == "-templates"]
    assert templates
    assert all(t.startswith("/t/http/") for t in templates)
    with pytest.raises(ScanError):
        build_argv("nuclei", "everything", "https://x/", "http://127.0.0.1:9", "/t")


def test_nuclei_output_is_parsed_defensively() -> None:
    matches = parse_jsonl((FIXTURES / "nuclei_sample.jsonl").read_bytes())
    assert [m["template_id"] for m in matches] == ["git-config", "tech-detect", "x-<script>"]
    git = matches[0]
    assert git["severity"] == "medium"
    assert git["cwe_ids"] == ["cwe-200"]
    assert git["cve_ids"] == []
    assert matches[1]["tags"] == ["tech"]
    assert matches[2]["severity"] == "high"
    assert parse_jsonl(b"x" * 70_000 + b"\n") == []


class GuardProbingRunner:
    """Fake Nuclei: checks the egress guard is live and restrictive while it 'runs'."""

    def __init__(self, output: bytes) -> None:
        self.output = output
        self.argv: list[str] = []
        self.env: Mapping[str, str] | None = None
        self.denied_status: int | None = None

    async def run(
        self, argv: Sequence[str], *, timeout_seconds: float, env: Mapping[str, str] | None
    ) -> ProcessResult:
        self.argv, self.env = list(argv), env
        proxy = argv[argv.index("-proxy") + 1]
        async with httpx.AsyncClient(proxy=proxy, trust_env=False, timeout=5) as client:
            self.denied_status = (await client.get("http://169.254.169.254/")).status_code
        return ProcessResult(stdout=self.output, stderr=b"", returncode=0)


async def test_nuclei_runs_behind_the_egress_guard() -> None:
    runner = GuardProbingRunner((FIXTURES / "nuclei_sample.jsonl").read_bytes())
    scanner = NucleiScanner(
        runner=runner, templates_dir="/t", version="3.11.1", templates_version="10.5.1"
    )
    target = scanner.target_for(AssetType.DOMAIN, "app.example.com")
    raw = await scanner.execute(ctx(target, "baseline"))

    assert runner.denied_status == 403
    assert runner.argv[runner.argv.index("-target") + 1] == "https://app.example.com/"
    assert raw.tool_versions == {"nuclei": "3.11.1", "nuclei-templates": "10.5.1"}
    assert raw.data["egress"]["denied_destinations"] == ["169.254.169.254:80"]

    observations = scanner.normalize_results(raw)
    assert observations[0].kind == "template_match"
    assert observations[0].key == "git-config https://app.example.com/.git/config"
    assert observations[1].key == "tech-detect:nginx https://app.example.com/"
    evidence = scanner.record_evidence(raw)[0].content
    assert "denied destination: 169.254.169.254:80" in evidence
    assert "git-config [medium]" in evidence

    findings = {f.rule_id: f for f in derive_findings(o.to_dict() for o in observations)}
    assert findings["nuclei.git-config"].severity is Severity.MEDIUM
    assert findings["nuclei.git-config"].cwe == 200
    assert findings["nuclei.tech-detect"].severity is Severity.INFO


async def test_nuclei_failure_is_safe() -> None:
    class Failing(GuardProbingRunner):
        async def run(self, argv: Sequence[str], **_: Any) -> ProcessResult:
            return ProcessResult(stdout=b"", stderr=b"panic", returncode=2)

    with pytest.raises(ScanError) as info:
        await NucleiScanner(runner=Failing(b"")).execute(
            ctx("https://app.example.com/", "baseline")
        )
    assert info.value.code == "tool_failed"


# ----------------------------------------------------------------------------- zap


class FakeZap:
    """Minimal emulation of the ZAP JSON API."""

    def __init__(self, *, spider_polls: int = 1) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []
        self.spider_polls = spider_polls
        self.keys: set[str] = set()

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/JSON/").rstrip("/")
        params = dict(request.url.params)
        self.calls.append((path, params))
        self.keys.add(request.headers.get("x-zap-api-key", ""))
        if path == "core/view/version":
            return httpx.Response(200, json={"version": "2.16.0"})
        if path == "context/action/newContext":
            return httpx.Response(200, json={"contextId": "7"})
        if path in ("spider/action/scan", "ascan/action/scan"):
            return httpx.Response(200, json={"scan": "3"})
        if path in ("spider/view/status", "ascan/view/status"):
            self.spider_polls -= 1
            return httpx.Response(200, json={"status": "100" if self.spider_polls <= 0 else "40"})
        if path == "pscan/view/recordsToScan":
            return httpx.Response(200, json={"recordsToScan": "0"})
        if path == "alert/view/alerts":
            return httpx.Response(200, content=(FIXTURES / "zap_alerts.json").read_bytes())
        if path == "core/view/urls":
            return httpx.Response(200, json={"urls": ["https://app.example.com/", "x"]})
        return httpx.Response(200, json={"Result": "OK"})

    def paths(self) -> list[str]:
        return [p for p, _ in self.calls]

    def params(self, path: str) -> dict[str, str]:
        return next(p for name, p in self.calls if name == path)


def zap(fake: FakeZap, **kwargs: Any) -> ZapScanner:
    return ZapScanner(
        api_key="k3y",
        proxy_bind="127.0.0.1",
        proxy_port=0,
        proxy_advertised_host="scanner-zap",
        transport=httpx.MockTransport(fake.handler),
        poll_interval=0,
        **kwargs,
    )


async def test_zap_baseline_is_scoped_and_passive() -> None:
    fake = FakeZap(spider_polls=2)
    scanner = zap(fake)
    raw = await scanner.execute(ctx("https://app.example.com/portal/", "baseline"))

    paths = fake.paths()
    assert fake.keys == {"k3y"}
    assert paths[1] == "core/action/newSession"
    assert paths[-1] == "core/action/newSession"  # cleaned up
    proxy = fake.params("network/action/setHttpProxy")
    assert proxy["host"] == "scanner-zap"
    assert int(proxy["port"]) > 0
    assert fake.params("context/action/includeInContext")["regex"] == include_regex(
        "https://app.example.com", "/portal/"
    )
    assert fake.params("spider/action/scan")["subtreeOnly"] == "true"
    assert not any(p.startswith("ascan/") for p in paths)
    assert raw.tool_versions == {"zap": "2.16.0"}
    assert raw.data["spider_completed"] is True
    assert raw.data["urls_discovered"] == 2

    observations = scanner.normalize_results(raw)
    assert [o.data["alert_ref"] for o in observations] == ["40012", "10038-1", "10202"]
    csp = observations[1]
    assert csp.key == "10038-1 https://app.example.com"
    assert csp.data["instance_count"] == 2
    findings = {f.rule_id: f for f in derive_findings(o.to_dict() for o in observations)}
    assert findings["zap.40012"].severity is Severity.HIGH
    assert findings["zap.10038"].confidence is Confidence.CONFIRMED
    assert findings["zap.10202"].confidence is Confidence.TENTATIVE
    assert "zap.10021" not in findings  # ZAP false positive dropped


async def test_zap_full_profile_is_intrusive_and_runs_active_scan() -> None:
    assert ZapScanner.technique_for("baseline") is Technique.ACTIVE
    assert ZapScanner.technique_for("full") is Technique.INTRUSIVE
    fake = FakeZap()
    await zap(fake).execute(ctx("https://app.example.com/", "full"))
    active = fake.params("ascan/action/scan")
    assert active["inScopeOnly"] == "true"
    assert active["contextId"] == "7"


async def test_zap_stops_spider_at_deadline() -> None:
    fake = FakeZap(spider_polls=10**9)
    await zap(fake).execute(ctx("https://app.example.com/", "baseline", timeout=0.01))
    assert "spider/action/stop" in fake.paths()


async def test_zap_errors_are_safe() -> None:
    with pytest.raises(ScanError) as info:
        await ZapScanner(api_key="").execute(ctx("https://app.example.com/", "baseline"))
    assert info.value.code == "zap_unavailable"

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(ScanError) as info:
        await ZapScanner(
            api_key="k", proxy_bind="127.0.0.1", proxy_port=0, transport=httpx.MockTransport(down)
        ).execute(ctx("https://app.example.com/", "baseline"))
    assert info.value.code == "zap_unavailable"


def test_alert_aggregation_bounds_instances() -> None:
    alerts = [
        {"pluginId": "1", "risk": "Low", "confidence": "Medium", "url": f"u{i}"} for i in range(50)
    ]
    (entry,) = aggregate_alerts(alerts)
    assert entry["instance_count"] == 50
    assert len(entry["instances"]) == 20
    assert json.dumps(entry)
