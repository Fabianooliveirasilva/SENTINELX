"""Operational tasks used to verify the worker pipeline end to end."""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from typing import TypedDict

from sentinelx_workers.celery_app import celery_app


class PingResult(TypedDict):
    status: str
    worker: str
    timestamp: str


@celery_app.task(name="system.ping")  # type: ignore[untyped-decorator]
def ping() -> PingResult:
    """Return a heartbeat proving a worker consumed a task from the broker."""
    return PingResult(
        status="ok",
        worker=socket.gethostname(),
        timestamp=datetime.now(UTC).isoformat(),
    )
