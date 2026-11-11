"""Cross-cutting HTTP behaviour: error envelope, correlation IDs, headers, CORS."""

from __future__ import annotations

import uuid
from collections.abc import Callable

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel

from app.core.errors import AppError
from tests.conftest import build_settings


def _client(app: FastAPI, base_url: str = "http://testserver") -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    return httpx.AsyncClient(transport=transport, base_url=base_url)


class _Payload(BaseModel):
    name: str
    count: int


class _ConflictError(AppError):
    status_code = 409
    code = "conflict"


def _app_with_test_routes(make_app: Callable[..., FastAPI]) -> FastAPI:
    app = make_app()

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("database password=hunter2 leaked")

    @app.get("/conflict")
    async def conflict() -> None:
        raise _ConflictError("Asset already registered.")

    @app.post("/echo")
    async def echo(payload: _Payload) -> _Payload:
        return payload

    return app


async def test_unknown_route_returns_error_envelope(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/does-not-exist")

    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "not_found"
    assert error["request_id"] == response.headers["X-Request-ID"]


async def test_unhandled_exception_is_generic_500(make_app: Callable[..., FastAPI]) -> None:
    async with _client(_app_with_test_routes(make_app)) as client:
        response = await client.get("/boom")

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert "hunter2" not in response.text
    assert response.json()["error"]["request_id"] == response.headers["X-Request-ID"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"


async def test_app_error_uses_its_status_and_code(make_app: Callable[..., FastAPI]) -> None:
    async with _client(_app_with_test_routes(make_app)) as client:
        response = await client.get("/conflict")

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "conflict"
    assert response.json()["error"]["message"] == "Asset already registered."


async def test_validation_error_does_not_echo_input(make_app: Callable[..., FastAPI]) -> None:
    async with _client(_app_with_test_routes(make_app)) as client:
        response = await client.post("/echo", json={"name": "s3cr3t-value", "count": "many"})

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"][0]["location"] == ["body", "count"]
    assert "s3cr3t-value" not in response.text


async def test_valid_inbound_request_id_is_propagated(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/health/live", headers={"X-Request-ID": "abc12345-req"})

    assert response.headers["X-Request-ID"] == "abc12345-req"


@pytest.mark.parametrize(
    "bad_id", ["short", "has spaces in it", "x" * 80, "<script>alert</script>"]
)
async def test_invalid_inbound_request_id_is_replaced(
    client: httpx.AsyncClient, bad_id: str
) -> None:
    response = await client.get("/api/v1/health/live", headers={"X-Request-ID": bad_id})

    returned = response.headers["X-Request-ID"]
    assert returned != bad_id
    uuid.UUID(returned)


async def test_security_headers_present(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/v1/health/live")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Content-Security-Policy"].startswith("default-src 'none'")
    assert response.headers["Cache-Control"] == "no-store"
    assert "Strict-Transport-Security" not in response.headers


async def test_hsts_enabled_in_production(make_app: Callable[..., FastAPI]) -> None:
    prod = build_settings(environment="production", secret_key="a" * 48)
    async with _client(make_app(settings_override=prod)) as client:
        response = await client.get("/api/v1/health/live")

    assert "max-age=" in response.headers["Strict-Transport-Security"]


async def test_docs_disabled_in_production(make_app: Callable[..., FastAPI]) -> None:
    prod = build_settings(environment="production", secret_key="a" * 48)
    async with _client(make_app(settings_override=prod)) as client:
        assert (await client.get("/api/docs")).status_code == 404
        assert (await client.get("/api/openapi.json")).status_code == 404


async def test_openapi_available_outside_production(client: httpx.AsyncClient) -> None:
    response = await client.get("/api/openapi.json")

    assert response.status_code == 200
    assert "/api/v1/health/ready" in response.json()["paths"]


async def test_untrusted_host_header_rejected(make_app: Callable[..., FastAPI]) -> None:
    async with _client(make_app(), base_url="http://evil.example") as client:
        response = await client.get("/api/v1/health/live")

    assert response.status_code == 400


async def test_cors_allows_only_configured_origins(make_app: Callable[..., FastAPI]) -> None:
    settings = build_settings(cors_allowed_origins=["http://localhost:5173"])
    async with _client(make_app(settings_override=settings)) as client:
        allowed = await client.get(
            "/api/v1/health/live", headers={"Origin": "http://localhost:5173"}
        )
        denied = await client.get("/api/v1/health/live", headers={"Origin": "https://evil.example"})

    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "access-control-allow-origin" not in denied.headers
