"""Prometheus metrics: request counters/latency, plus operational gauges read at scrape time.

* Labels are bounded: the route *template* (never the raw path), method and status.
  No user, project, asset or finding identifier ever becomes a label.
* ``GET /metrics`` is not under ``/api`` so the reverse proxy does not publish it;
  it is meant for the internal network and can additionally require a bearer token.
"""

from __future__ import annotations

import hmac
import time
from typing import Any, Final

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.logging import get_logger
from app.models import ScanJob

logger = get_logger(__name__)

REGISTRY: Final = CollectorRegistry(auto_describe=True)
METRICS_PATH: Final = "/metrics"
API_PREFIX: Final = "/api/v1"
CONTENT_TYPE: Final = "text/plain; version=0.0.4; charset=utf-8"
QUEUES: Final = ("orchestrator", "scans", "scans.zap", "intel", "ai", "notifications")
SCAN_STATUSES: Final = ("pending", "queued", "running", "completed", "failed", "cancelled")

REQUESTS = Counter(
    "sentinelx_http_requests_total",
    "HTTP requests handled by the API.",
    ("method", "route", "status"),
    registry=REGISTRY,
)
LATENCY = Histogram(
    "sentinelx_http_request_duration_seconds",
    "HTTP request latency.",
    ("method", "route"),
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
    registry=REGISTRY,
)
SCAN_JOBS = Gauge(
    "sentinelx_scan_jobs", "Scan jobs by status (all time).", ("status",), registry=REGISTRY
)
QUEUE_LENGTH = Gauge(
    "sentinelx_queue_length", "Messages waiting in a worker queue.", ("queue",), registry=REGISTRY
)
BUILD_INFO = Gauge("sentinelx_build_info", "Application version.", ("version",), registry=REGISTRY)


class MetricsMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") == METRICS_PATH:
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            template = _route_template(scope)
            method = str(scope.get("method", "GET"))
            REQUESTS.labels(method, template, str(status)).inc()
            LATENCY.labels(method, template).observe(time.perf_counter() - started)


def _route_template(scope: Scope) -> str:
    """The matched route template (bounded cardinality), or ``unmatched``."""
    route = scope.get("route")
    template = getattr(route, "path", None)
    if not template:
        return "unmatched"
    # Routes of the nested API router report their path without the mount prefix.
    if str(scope.get("path", "")).startswith(API_PREFIX) and not template.startswith(API_PREFIX):
        return f"{API_PREFIX}{template}"
    return str(template)


def token_valid(expected: str | None, header: str | None) -> bool:
    """With no configured token the endpoint relies on network isolation."""
    if not expected:
        return True
    scheme, _, provided = (header or "").partition(" ")
    return scheme.lower() == "bearer" and hmac.compare_digest(provided.encode(), expected.encode())


async def render(session: AsyncSession, redis: Any, version: str) -> bytes:
    """Refresh the scrape-time gauges, then serialize the registry."""
    SCAN_JOBS.clear()
    counts = dict(
        (await session.execute(select(ScanJob.status, func.count()).group_by(ScanJob.status))).all()
    )
    for status in SCAN_STATUSES:
        SCAN_JOBS.labels(status).set(int(counts.get(status, 0)))
    QUEUE_LENGTH.clear()
    for queue in QUEUES:
        try:
            QUEUE_LENGTH.labels(queue).set(int(await redis.llen(queue)))
        except Exception as exc:  # noqa: BLE001 - a Redis outage must not break the scrape
            logger.debug("queue_length_unavailable", queue=queue, error=type(exc).__name__)
    BUILD_INFO.clear()
    BUILD_INFO.labels(version).set(1)
    return generate_latest(REGISTRY)
