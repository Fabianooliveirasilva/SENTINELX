"""Scan execution: authoritative scope check, then bounded execution.

``execute_scan`` is what the scanner worker runs. It receives a JSON request
(scanner, profile, target and a snapshot of the project's assets and
authorizations), re-evaluates scope *at execution time* — resolving DNS now and
pinning the resulting addresses — and only then runs the scanner against those
addresses. The outcome is JSON so it can travel back over the broker.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinelx_security.scanners.base import (
    SCANNER_PACKAGE_VERSION,
    Evidence,
    Observation,
    ScanContext,
    ScanError,
    Scanner,
    ScannerName,
)
from sentinelx_security.scope import ScopeEngine, parse_target
from sentinelx_security.scope.serialization import asset_from_dict, decision_to_dict
from sentinelx_security.scope.targets import parse_ip

MAX_OBSERVATIONS = 5000


@dataclass(frozen=True, slots=True)
class ScanRequest:
    job_id: str
    scanner: ScannerName
    profile: str
    target: str
    assets: list[dict[str, Any]]
    timeout_seconds: float = 240.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "scanner": self.scanner.value,
            "profile": self.profile,
            "target": self.target,
            "assets": self.assets,
            "timeout_seconds": self.timeout_seconds,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScanRequest:
        return cls(
            job_id=str(data["job_id"]),
            scanner=ScannerName(data["scanner"]),
            profile=str(data["profile"]),
            target=str(data["target"]),
            assets=list(data["assets"]),
            timeout_seconds=float(data.get("timeout_seconds", 240.0)),
        )


@dataclass(slots=True)
class ScanOutcome:
    status: str  # completed | denied | failed
    decision: dict[str, Any] | None
    observations: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, str]] = field(default_factory=list)
    tool_versions: dict[str, str] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None
    started_at: str = ""
    finished_at: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "decision": self.decision,
            "observations": self.observations,
            "evidence": self.evidence,
            "tool_versions": self.tool_versions,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
        }


async def execute_scan(
    request: ScanRequest,
    engine: ScopeEngine,
    scanners: Mapping[ScannerName, Scanner],
    *,
    now: datetime | None = None,
) -> ScanOutcome:
    started = datetime.now(UTC)
    clock = time.perf_counter()
    tool_versions = {"sentinelx-security": SCANNER_PACKAGE_VERSION}

    def finish(outcome: ScanOutcome) -> ScanOutcome:
        outcome.started_at = started.isoformat()
        outcome.finished_at = datetime.now(UTC).isoformat()
        outcome.duration_ms = int((time.perf_counter() - clock) * 1000)
        outcome.tool_versions = {**tool_versions, **outcome.tool_versions}
        return outcome

    scanner = scanners.get(request.scanner)
    if scanner is None:
        return finish(
            ScanOutcome(
                "failed",
                None,
                error_code="scanner_unavailable",
                error_message="This scanner is not available on the worker.",
            )
        )
    if request.profile not in scanner.profiles:
        return finish(
            ScanOutcome(
                "failed", None, error_code="invalid_profile", error_message="Unknown scan profile."
            )
        )

    assets = [asset_from_dict(a) for a in request.assets]
    decision = await scanner.validate_scope(
        engine, request.target, assets, now or started, profile=request.profile
    )
    decision_dict = decision_to_dict(decision)
    if not decision.allowed:
        reason = decision.reasons[0].message if decision.reasons else "Target is out of scope."
        return finish(
            ScanOutcome("denied", decision_dict, error_code="scope_denied", error_message=reason)
        )

    ctx = ScanContext(
        target=parse_target(decision.target),
        pinned_addresses=tuple(parse_ip(v.address) for v in decision.addresses if v.allowed),
        profile=request.profile,
        timeout_seconds=request.timeout_seconds,
    )
    try:
        raw = await scanner.execute(ctx)
        observations: list[Observation] = scanner.normalize_results(raw)[:MAX_OBSERVATIONS]
        evidence: list[Evidence] = scanner.record_evidence(raw)
    except Exception as exc:  # noqa: BLE001 - every failure becomes a safe ScanError
        error: ScanError = scanner.handle_errors(exc)
        return finish(
            ScanOutcome("failed", decision_dict, error_code=error.code, error_message=error.message)
        )

    return finish(
        ScanOutcome(
            "completed",
            decision_dict,
            observations=[o.to_dict() for o in observations],
            evidence=[e.to_dict() for e in evidence],
            tool_versions=dict(raw.tool_versions),
        )
    )
