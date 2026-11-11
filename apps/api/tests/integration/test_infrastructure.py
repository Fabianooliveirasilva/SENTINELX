"""Integration tests against real PostgreSQL and Redis.

Run with real infrastructure configured through SENTINELX_* variables::

    uv run pytest -m integration

These run in CI (service containers) and against `docker compose`.
"""

from __future__ import annotations

import httpx
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from redis.asyncio import Redis
from sqlalchemy import text

from app.core.config import Settings
from app.db.session import create_engine
from app.main import create_app
from tests.integration.conftest import ALEMBIC_INI

pytestmark = pytest.mark.integration


@pytest.fixture
def real_settings() -> Settings:
    return Settings()


async def test_postgres_accepts_queries_and_migrations_applied(real_settings: Settings) -> None:
    engine = create_engine(real_settings)
    try:
        async with engine.connect() as connection:
            assert (await connection.execute(text("SELECT 1"))).scalar_one() == 1
            version = await connection.execute(text("SELECT version_num FROM alembic_version"))
            head = ScriptDirectory.from_config(Config(str(ALEMBIC_INI))).get_current_head()
            assert version.scalar_one() == head
    finally:
        await engine.dispose()


async def test_redis_ping(real_settings: Settings) -> None:
    client = Redis.from_url(real_settings.redis_url.get_secret_value())
    try:
        assert await client.ping() is True
    finally:
        await client.aclose()


async def test_readiness_endpoint_reports_ok(real_settings: Settings) -> None:
    app = create_app(real_settings)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://localhost") as client,
    ):
        response = await client.get("/api/v1/health/ready")

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "ok"
