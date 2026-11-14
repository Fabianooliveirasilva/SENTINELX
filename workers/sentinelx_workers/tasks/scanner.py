"""Sandboxed scan execution (runs in the scanner container, without DB access)."""

from __future__ import annotations

import asyncio
from typing import Any

from app.core.logging import get_logger
from app.services.scan_dispatch import EXECUTE_TASK
from sentinelx_security.scanners import ScanOutcome, ScanRequest, build_scanners, execute_scan
from sentinelx_workers.scanner_app import get_scanner_settings, scanner_app

# Slack for the scope check and result normalization beyond the scan timeout.
OVERALL_GRACE_SECONDS = 20

logger = get_logger(__name__)


async def run_request(request: ScanRequest) -> dict[str, Any]:
    settings = get_scanner_settings()
    engine = settings.scope_engine()
    scanners = build_scanners(settings.scanner_config())
    try:
        outcome = await asyncio.wait_for(
            execute_scan(request, engine, scanners),
            timeout=request.timeout_seconds + OVERALL_GRACE_SECONDS,
        )
    except TimeoutError:
        outcome = ScanOutcome(
            "failed",
            None,
            error_code="timeout",
            error_message="The scan exceeded its time limit.",
        )
    return outcome.to_dict()


@scanner_app.task(name=EXECUTE_TASK, shared=False)  # type: ignore[untyped-decorator]
def execute(request: dict[str, Any] | None) -> dict[str, Any] | None:
    if request is None:  # the orchestrator skipped the job (cancelled or halted)
        return None
    parsed = ScanRequest.from_dict(request)
    logger.info("scan_executing", scan_job_id=parsed.job_id, scanner=parsed.scanner.value)
    result = asyncio.run(run_request(parsed))
    logger.info(
        "scan_executed",
        scan_job_id=parsed.job_id,
        status=result["status"],
        error_code=result["error_code"],
        observations=len(result["observations"]),
    )
    return result
