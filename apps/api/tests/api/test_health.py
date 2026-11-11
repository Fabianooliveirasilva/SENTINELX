from __future__ import annotations

from collections.abc import Callable

import httpx
from fastapi import FastAPI

from app.main import create_app
from tests.conftest import StubCheck, build_settings


def _client(app: FastAPI) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


async def test_liveness_returns_ok(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_readiness_ok_when_all_components_healthy(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/health/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert set(body["components"]) == {"database", "redis"}
    assert all(c["status"] == "ok" and c["latency_ms"] >= 0 for c in body["components"].values())


async def test_readiness_503_when_a_component_fails(make_app: Callable[..., FastAPI]) -> None:
    app = make_app(StubCheck("database"), StubCheck("redis", error=ConnectionError("secret-host")))

    async with _client(app) as client:
        response = await client.get("/api/v1/health/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "unavailable"
    assert body["components"]["database"]["status"] == "ok"
    assert body["components"]["redis"] == {
        "status": "unavailable",
        "latency_ms": None,
        "error": "unreachable",
    }
    # Exception messages must never leak to clients.
    assert "secret-host" not in response.text


async def test_readiness_reports_timeout(make_app: Callable[..., FastAPI]) -> None:
    app = make_app(StubCheck("database", delay=1.0), StubCheck("redis"))

    async with _client(app) as client:
        response = await client.get("/api/v1/health/ready")

    assert response.status_code == 503
    assert response.json()["components"]["database"]["error"] == "timeout"


async def test_lifespan_wires_real_checks_and_reports_unreachable_infrastructure() -> None:
    """Exercises the real lifespan: engine + Redis client against closed ports."""
    app = create_app(build_settings(health_check_timeout_seconds=1.0))
    async with app.router.lifespan_context(app), _client(app) as client:
        response = await client.get("/api/v1/health/ready")

    assert response.status_code == 503
    components = response.json()["components"]
    assert components["database"]["status"] == "unavailable"
    assert components["redis"]["status"] == "unavailable"
