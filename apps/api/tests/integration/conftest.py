"""Fixtures for tests that run against real PostgreSQL.

Configuration comes from SENTINELX_* environment variables (see docs/TESTING.md).
Migrations are applied once per session; every test starts from empty tables
(the RBAC seed from the migration is preserved).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from alembic.config import Config
from fakeredis import FakeAsyncRedis
from fastapi import FastAPI
from sqlalchemy import text

from app.core.config import Settings
from app.core.permissions import RoleName
from app.core.security.passwords import PasswordService
from app.db.session import create_engine
from app.main import create_app
from app.models import User
from app.repositories.users import UserRepository
from app.services.email import EmailMessage
from app.services.scan_dispatch import DispatchHandle
from sentinelx_security.scope import NetworkPolicy, ScopeEngine, StaticResolver, parse_lab_networks

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"
TENANT_TABLES = (
    "platform_settings",
    "scan_evidence",
    "scan_results",
    "scan_jobs",
    "audit_logs",
    "asset_authorizations",
    "assets",
    "password_reset_tokens",
    "refresh_tokens",
    "project_members",
    "projects",
    "users",
)
DEFAULT_PASSWORD = "correct-horse-battery-staple"

# Deterministic DNS for scope tests (no network access in the test suite).
TEST_DNS = {
    "example.com": ["93.184.215.14"],
    "www.example.com": ["93.184.215.14"],
    "cdn.example.com": ["151.101.1.1"],
    "rebind.example.com": ["93.184.215.14", "127.0.0.1"],
    "juice.lab.example.com": ["10.20.0.5"],
}


class RecordingDispatcher:
    """Captures published scan chains instead of talking to a broker."""

    def __init__(self) -> None:
        self.dispatched: list[str] = []
        self.revoked: list[str] = []
        self.fail = False

    def dispatch(self, job_id: str, timeout_seconds: int) -> DispatchHandle:
        if self.fail:
            raise ConnectionError("broker down")
        self.dispatched.append(job_id)
        return DispatchHandle(execute_task_id=f"exec-{job_id}")

    def revoke(self, task_id: str) -> None:
        self.revoked.append(task_id)


class MemoryEmailSender:
    def __init__(self) -> None:
        self.outbox: list[EmailMessage] = []

    async def send(self, message: EmailMessage) -> None:
        self.outbox.append(message)


def integration_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "test",
        "cookie_secure": False,  # httpx does not send Secure cookies over http://testserver
        "argon2_time_cost": 1,
        "argon2_memory_cost_kib": 1024,
        "allowed_hosts": ["testserver", "localhost", "127.0.0.1"],
        "rate_limit_login_per_minute": 1000,
        "rate_limit_password_reset_per_hour": 1000,
        "rate_limit_register_per_hour": 1000,
        "rate_limit_refresh_per_minute": 1000,
        "rate_limit_scope_check_per_minute": 5,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.fixture(scope="session")
def migrated_database() -> None:
    command.upgrade(Config(str(ALEMBIC_INI)), "head")
    return


@dataclass
class ApiStack:
    app: FastAPI
    client: httpx.AsyncClient
    email: MemoryEmailSender
    settings: Settings
    dispatcher: RecordingDispatcher
    users: dict[str, User] = field(default_factory=dict)

    async def create_user(
        self,
        email: str,
        *,
        role: RoleName = RoleName.VIEWER,
        password: str = DEFAULT_PASSWORD,
        full_name: str = "Test User",
        is_active: bool = True,
    ) -> User:
        passwords: PasswordService = self.app.state.password_service
        async with self.app.state.session_factory() as session:
            repo = UserRepository(session)
            user = User(
                id=uuid.uuid4(),
                email=email.lower(),
                full_name=full_name,
                password_hash=await passwords.hash(password),
                role_id=(await repo.get_role(role)).id,
                is_active=is_active,
            )
            session.add(user)
            await session.commit()
            self.users[email] = user
            return user

    async def login(self, email: str, password: str = DEFAULT_PASSWORD) -> dict[str, str]:
        response = await self.client.post(
            "/api/v1/auth/login", json={"email": email, "password": password}
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    async def user_headers(self, email: str, role: RoleName = RoleName.VIEWER) -> dict[str, str]:
        await self.create_user(email, role=role)
        return await self.login(email)


async def _truncate(settings: Settings) -> None:
    engine = create_engine(settings)
    try:
        async with engine.begin() as connection:
            await connection.execute(text(f"TRUNCATE {', '.join(TENANT_TABLES)} CASCADE"))
    finally:
        await engine.dispose()


@pytest.fixture
def stack_settings() -> Settings:
    """Override in a test module to customise settings for the whole module."""
    return integration_settings()


@pytest.fixture
async def stack(migrated_database: None, stack_settings: Settings) -> AsyncIterator[ApiStack]:
    await _truncate(stack_settings)
    app = create_app(stack_settings)
    async with app.router.lifespan_context(app):
        app.state.redis = FakeAsyncRedis()
        app.state.scope_engine = ScopeEngine(
            NetworkPolicy(parse_lab_networks(stack_settings.scope_lab_networks)),
            StaticResolver(TEST_DNS),
            lab_domains=stack_settings.scope_lab_domains,
        )
        email = MemoryEmailSender()
        app.state.email_sender = email
        dispatcher = RecordingDispatcher()
        app.state.scan_dispatcher = dispatcher
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield ApiStack(
                app=app, client=client, email=email, settings=stack_settings, dispatcher=dispatcher
            )
        await app.state.redis.aclose()
