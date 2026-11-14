"""Scan executor: authoritative scope check before any execution."""

from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import ClassVar

import pytest

from sentinelx_security.scanners import (
    Observation,
    RawOutput,
    ScanContext,
    Scanner,
    ScannerName,
    ScanRequest,
    execute_scan,
)
from sentinelx_security.scope import (
    AssetType,
    AuthorizationGrant,
    NetworkPolicy,
    ScopeAsset,
    ScopeEngine,
    StaticResolver,
    Technique,
)
from sentinelx_security.scope.serialization import (
    asset_from_dict,
    asset_to_dict,
    decision_from_dict,
    decision_to_dict,
)

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
ENGINE = ScopeEngine(
    NetworkPolicy(),
    StaticResolver({"example.com": ["93.184.215.14"], "rebind.example.com": ["127.0.0.1"]}),
)


class SpyScanner(Scanner):
    name: ClassVar[ScannerName] = ScannerName.NMAP
    technique: ClassVar[Technique] = Technique.ACTIVE
    description: ClassVar[str] = "spy"
    supported_asset_types = frozenset({AssetType.DOMAIN})

    def __init__(self, error: Exception | None = None) -> None:
        self.contexts: list[ScanContext] = []
        self.error = error

    async def execute(self, ctx: ScanContext) -> RawOutput:
        self.contexts.append(ctx)
        if self.error:
            raise self.error
        return RawOutput(data={"ok": True}, tool_versions={"spy": "1.0"})

    def normalize_results(self, raw: RawOutput) -> list[Observation]:
        return [Observation(kind="open_port", key="93.184.215.14:443/tcp", data={"port": 443})]


def _asset(
    value: str, *, active: bool = True, ranges: tuple[str, ...] = ("93.184.215.0/24",)
) -> dict[str, object]:
    asset = ScopeAsset(
        id=uuid.uuid4(),
        type=AssetType.DOMAIN,
        value=value,
        authorizations=(
            AuthorizationGrant(
                id=uuid.uuid4(),
                valid_from=NOW - timedelta(days=1),
                valid_until=NOW + timedelta(days=1),
                allow_active=active,
                ip_ranges=tuple(ipaddress.ip_network(r) for r in ranges),
            ),
        ),
    )
    return asset_to_dict(asset)


def _request(target: str, *assets: dict[str, object], profile: str = "default") -> ScanRequest:
    data = ScanRequest(
        job_id="job-1",
        scanner=ScannerName.NMAP,
        profile=profile,
        target=target,
        assets=list(assets),
    ).to_dict()
    # Must survive the JSON broker round trip unchanged.
    return ScanRequest.from_dict(json.loads(json.dumps(data)))


async def test_allowed_scan_runs_against_pinned_addresses_only() -> None:
    spy = SpyScanner()

    outcome = await execute_scan(
        _request("example.com", _asset("example.com")), ENGINE, {ScannerName.NMAP: spy}, now=NOW
    )

    assert outcome.status == "completed"
    assert [str(a) for a in spy.contexts[0].pinned_addresses] == ["93.184.215.14"]
    assert outcome.observations[0]["key"] == "93.184.215.14:443/tcp"
    assert outcome.tool_versions["spy"] == "1.0"
    assert "sentinelx-security" in outcome.tool_versions
    assert outcome.decision is not None
    assert outcome.decision["allowed"] is True
    json.dumps(outcome.to_dict())  # JSON-serializable for the broker


@pytest.mark.parametrize(
    ("target", "asset", "code"),
    [
        ("example.com", _asset("example.com", active=False), "technique_not_authorized"),
        ("rebind.example.com", _asset("rebind.example.com"), "loopback_address"),
        ("other.example.com", _asset("example.com"), "no_matching_asset"),
    ],
)
async def test_denied_scans_never_execute(target: str, asset: dict[str, object], code: str) -> None:
    spy = SpyScanner()

    outcome = await execute_scan(_request(target, asset), ENGINE, {ScannerName.NMAP: spy}, now=NOW)

    assert outcome.status == "denied"
    assert outcome.error_code == "scope_denied"
    assert spy.contexts == []
    assert outcome.decision is not None
    assert code in {r["code"] for r in outcome.decision["reasons"]}


async def test_scanner_failures_become_safe_errors() -> None:
    spy = SpyScanner(error=RuntimeError("internal detail /etc/secret"))

    outcome = await execute_scan(
        _request("example.com", _asset("example.com")), ENGINE, {ScannerName.NMAP: spy}, now=NOW
    )

    assert outcome.status == "failed"
    assert outcome.error_code == "scanner_error"
    assert "secret" not in (outcome.error_message or "")


async def test_unknown_profiles_and_scanners_fail_closed() -> None:
    spy = SpyScanner()

    bad_profile = await execute_scan(
        _request("example.com", _asset("example.com"), profile="--script=all"),
        ENGINE,
        {ScannerName.NMAP: spy},
        now=NOW,
    )
    missing = await execute_scan(
        _request("example.com", _asset("example.com")), ENGINE, {}, now=NOW
    )

    assert (bad_profile.status, bad_profile.error_code) == ("failed", "invalid_profile")
    assert (missing.status, missing.error_code) == ("failed", "scanner_unavailable")
    assert spy.contexts == []


def test_scope_serialization_round_trips() -> None:
    asset = _asset("example.com")

    assert asset_to_dict(asset_from_dict(asset)) == asset


async def test_decision_serialization_round_trips() -> None:
    decision = await ENGINE.evaluate(
        "example.com", Technique.ACTIVE, [asset_from_dict(_asset("example.com"))], NOW
    )

    assert decision_from_dict(json.loads(json.dumps(decision_to_dict(decision)))) == decision
