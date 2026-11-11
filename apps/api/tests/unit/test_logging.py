from __future__ import annotations

import json
import logging

import pytest
import structlog

from app.core.logging import (
    REDACTED,
    configure_logging,
    get_logger,
    redact_sensitive_values,
    scrub_url_credentials,
)


def test_redacts_sensitive_keys_recursively() -> None:
    event = {
        "event": "login",
        "password": "hunter2",
        "user": {"email": "a@b.c", "access_token": "abc", "nested": [{"api_key": "k"}]},
        "Authorization": "Bearer xyz",
        "count": 3,
    }

    result = redact_sensitive_values(None, "info", event)

    assert result["password"] == REDACTED
    assert result["Authorization"] == REDACTED
    assert result["user"]["access_token"] == REDACTED
    assert result["user"]["nested"][0]["api_key"] == REDACTED
    assert result["user"]["email"] == "a@b.c"
    assert result["count"] == 3


def test_json_log_output_is_structured_and_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(level="INFO", json_logs=True)
    structlog.contextvars.bind_contextvars(request_id="req-12345678")
    try:
        get_logger("test").info("user_event", secret="do-not-log", outcome="ok")
    finally:
        structlog.contextvars.clear_contextvars()

    line = capsys.readouterr().out.strip().splitlines()[-1]
    record = json.loads(line)
    assert record["event"] == "user_event"
    assert record["request_id"] == "req-12345678"
    assert record["secret"] == REDACTED
    assert record["level"] == "info"
    assert record["timestamp"].endswith("Z")


def test_stdlib_loggers_are_routed_through_structlog(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(level="INFO", json_logs=True)

    logging.getLogger("uvicorn.error").info("server started")

    record = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert record["event"] == "server started"
    assert record["logger"] == "uvicorn.error"


def test_scrubs_credentials_embedded_in_urls() -> None:
    message = "connect failed: postgresql+asyncpg://admin:s3cr3t@db:5432/app and redis://:pw@r:6379"

    scrubbed = scrub_url_credentials(message)

    assert "s3cr3t" not in scrubbed
    assert "postgresql+asyncpg://admin:[REDACTED]@db:5432/app" in scrubbed
    assert "redis://:[REDACTED]@r:6379" in scrubbed


def test_exception_tracebacks_are_scrubbed(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging(level="INFO", json_logs=True)

    try:
        raise ConnectionError("cannot reach postgresql://svc:topsecret@db/x")
    except ConnectionError as exc:
        get_logger("test").error("failure", exc_info=exc)

    output = capsys.readouterr().out
    assert "topsecret" not in output
    assert "Traceback" in output
