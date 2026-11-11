from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from app.core.config import Settings
from app.dependencies.health import get_health_service
from app.main import create_app
from app.services.health import HealthService


class StubCheck:
    """Deterministic health check used to exercise success/failure paths."""

    def __init__(self, name: str, *, error: BaseException | None = None, delay: float = 0) -> None:
        self.name = name
        self._error = error
        self._delay = delay

    async def check(self) -> None:
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._error is not None:
            raise self._error


def build_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "test",
        "secret_key": "test-only-secret-key-not-for-production-use-0000",
        "database_url": "postgresql+asyncpg://u:p@127.0.0.1:1/db",
        "redis_url": "redis://127.0.0.1:1/0",
        "allowed_hosts": ["testserver", "localhost", "127.0.0.1"],
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.fixture
def settings() -> Settings:
    return build_settings()


@pytest.fixture
def make_app(settings: Settings) -> Callable[..., FastAPI]:
    def _make(*checks: StubCheck, settings_override: Settings | None = None) -> FastAPI:
        app = create_app(settings_override or settings)
        service = HealthService(
            checks or (StubCheck("database"), StubCheck("redis")),
            timeout_seconds=0.2,
            version="test",
        )
        app.dependency_overrides[get_health_service] = lambda: service
        return app

    return _make


@pytest.fixture
async def client(make_app: Callable[..., FastAPI]) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=make_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c
