"""Liveness/readiness checks for infrastructure dependencies.

Checks run concurrently, each bounded by a timeout. Failure details are logged
server-side only; the public report exposes a coarse status, never exception
messages (which can contain hostnames, credentials or driver internals).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from typing import Protocol

from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.logging import get_logger
from app.schemas.health import ComponentHealth, ComponentStatus, ReadinessReport

logger = get_logger(__name__)


class HealthCheck(Protocol):
    name: str

    async def check(self) -> None:
        """Return normally when healthy; raise any exception otherwise."""


class DatabaseHealthCheck:
    name = "database"

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def check(self) -> None:
        async with self._engine.connect() as connection:
            await connection.execute(text("SELECT 1"))


class RedisHealthCheck:
    name = "redis"

    def __init__(self, client: Redis) -> None:
        self._client = client

    async def check(self) -> None:
        if not await self._client.ping():
            raise ConnectionError("redis ping returned a falsy response")


class HealthService:
    def __init__(self, checks: Sequence[HealthCheck], *, timeout_seconds: float, version: str):
        self._checks = tuple(checks)
        self._timeout = timeout_seconds
        self._version = version

    async def readiness(self) -> ReadinessReport:
        results = await asyncio.gather(*(self._run(check) for check in self._checks))
        components = dict(results)
        healthy = all(c.status is ComponentStatus.OK for c in components.values())
        return ReadinessReport(
            status=ComponentStatus.OK if healthy else ComponentStatus.UNAVAILABLE,
            version=self._version,
            components=components,
        )

    async def _run(self, check: HealthCheck) -> tuple[str, ComponentHealth]:
        started = time.perf_counter()
        try:
            async with asyncio.timeout(self._timeout):
                await check.check()
        except TimeoutError:
            logger.warning("health_check_timeout", component=check.name, timeout_s=self._timeout)
            return check.name, ComponentHealth(status=ComponentStatus.UNAVAILABLE, error="timeout")
        except Exception as exc:  # noqa: BLE001 - any failure means "not ready"
            logger.warning("health_check_failed", component=check.name, exc_type=type(exc).__name__)
            return check.name, ComponentHealth(
                status=ComponentStatus.UNAVAILABLE, error="unreachable"
            )
        latency_ms = round((time.perf_counter() - started) * 1000, 2)
        return check.name, ComponentHealth(status=ComponentStatus.OK, latency_ms=latency_ms)
