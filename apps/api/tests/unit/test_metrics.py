"""Metrics helpers and the disabled switch."""

from __future__ import annotations

import httpx
import pytest

from app.core.config import Settings
from app.main import create_app
from app.observability.metrics import token_valid


@pytest.mark.parametrize(
    ("expected", "header", "ok"),
    [
        (None, None, True),  # network isolation only
        ("s3cret", "Bearer s3cret", True),
        ("s3cret", "bearer s3cret", True),
        ("s3cret", "Bearer other", False),
        ("s3cret", "s3cret", False),
        ("s3cret", None, False),
        ("s3cret", "Basic czNjcmV0", False),
    ],
)
def test_token_validation(expected: str | None, header: str | None, ok: bool) -> None:
    assert token_valid(expected, header) is ok


async def test_metrics_endpoint_can_be_disabled(settings: Settings) -> None:
    app = create_app(settings.model_copy(update={"metrics_enabled": False}))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        assert (await client.get("/metrics")).status_code == 404
