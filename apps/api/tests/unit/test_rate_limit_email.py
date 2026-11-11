from __future__ import annotations

import pytest
from fakeredis import FakeAsyncRedis
from redis.asyncio import Redis

from app.core.errors import RateLimitedError
from app.services.email import (
    ConsoleEmailSender,
    DisabledEmailSender,
    EmailMessage,
    build_email_sender,
)
from app.services.rate_limit import RateLimiter
from tests.conftest import build_settings


async def test_fixed_window_allows_up_to_limit() -> None:
    limiter = RateLimiter(FakeAsyncRedis())

    results = [await limiter.hit("login", "1.2.3.4", limit=2, window_seconds=60) for _ in range(3)]

    assert [r.allowed for r in results] == [True, True, False]
    assert results[-1].remaining == 0
    assert 0 < results[-1].retry_after_seconds <= 60


async def test_limits_are_isolated_per_scope_and_identifier() -> None:
    limiter = RateLimiter(FakeAsyncRedis())
    await limiter.hit("login", "a", limit=1, window_seconds=60)

    assert (await limiter.hit("login", "b", limit=1, window_seconds=60)).allowed
    assert (await limiter.hit("reset", "a", limit=1, window_seconds=60)).allowed


async def test_identifiers_are_not_stored_in_clear_text() -> None:
    redis = FakeAsyncRedis()
    await RateLimiter(redis).hit("login", "alice@example.com", limit=5, window_seconds=60)

    keys = [k.decode() if isinstance(k, bytes) else k for k in await redis.keys("*")]

    assert keys
    assert all("alice" not in k for k in keys)


async def test_enforce_raises_with_retry_after() -> None:
    limiter = RateLimiter(FakeAsyncRedis())
    await limiter.enforce("x", "id", limit=1, window_seconds=30)

    with pytest.raises(RateLimitedError) as excinfo:
        await limiter.enforce("x", "id", limit=1, window_seconds=30)

    assert excinfo.value.status_code == 429
    assert excinfo.value.headers is not None
    assert int(excinfo.value.headers["Retry-After"]) > 0


async def test_fails_open_when_redis_is_unavailable() -> None:
    unreachable = Redis.from_url("redis://127.0.0.1:1/0", socket_connect_timeout=0.2)
    try:
        result = await RateLimiter(unreachable).hit("login", "id", limit=1, window_seconds=60)
    finally:
        await unreachable.aclose()

    assert result.allowed


async def test_console_email_sender_writes_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    await ConsoleEmailSender().send(EmailMessage(to="a@b.c", subject="Hi", body="Body text"))

    captured = capsys.readouterr()
    assert "Body text" in captured.err
    assert captured.out == ""


async def test_disabled_email_sender_drops_content(capsys: pytest.CaptureFixture[str]) -> None:
    await DisabledEmailSender().send(EmailMessage(to="a@b.c", subject="S", body="secret-link"))

    assert "secret-link" not in capsys.readouterr().out


def test_email_backend_selection() -> None:
    assert isinstance(build_email_sender(build_settings()), ConsoleEmailSender)
    assert isinstance(
        build_email_sender(build_settings(email_backend="disabled")), DisabledEmailSender
    )
