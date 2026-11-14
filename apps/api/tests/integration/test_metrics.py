"""Prometheus endpoint: content, bounded labels, optional bearer token."""

from __future__ import annotations

import pytest

from app.core.config import Settings
from tests.integration.conftest import ApiStack, integration_settings
from tests.integration.test_scans import _asset, _request, _setup

pytestmark = pytest.mark.integration


@pytest.fixture
def stack_settings() -> Settings:
    return integration_settings(metrics_token="m" * 32)


async def test_metrics_requires_the_token_and_exposes_bounded_labels(stack: ApiStack) -> None:
    assert (await stack.client.get("/metrics")).status_code == 401
    assert (
        await stack.client.get("/metrics", headers={"Authorization": "Bearer wrong"})
    ).status_code == 401
    admin, analyst, project = await _setup(stack)
    asset = await _asset(stack, analyst, project)
    await _request(stack, analyst, project, asset)
    await stack.client.get(f"/api/v1/projects/{project}", headers=admin)

    response = await stack.client.get("/metrics", headers={"Authorization": f"Bearer {'m' * 32}"})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text
    # Route templates, never concrete identifiers.
    assert 'route="/api/v1/projects/{project_id}"' in body
    assert project not in body
    assert asset not in body
    assert "admin@example.com" not in body
    assert 'sentinelx_scan_jobs{status="queued"}' in body
    assert "sentinelx_build_info{version=" in body
    assert "sentinelx_http_request_duration_seconds_bucket" in body
    # The scrape itself is not counted, and unknown paths do not create labels.
    await stack.client.get("/definitely/not/here")
    again = (
        await stack.client.get("/metrics", headers={"Authorization": f"Bearer {'m' * 32}"})
    ).text
    assert "/definitely/not/here" not in again
    assert 'route="unmatched"' in again
    assert 'route="/metrics"' not in again
