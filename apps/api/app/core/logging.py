"""Structured logging.

Every log line is a structured event (JSON in production) enriched with the
request/correlation context bound through ``structlog.contextvars``. A redaction
processor masks values whose keys look sensitive so tokens, passwords and DSNs
never reach log storage, even if a developer logs them by mistake.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Mapping
from typing import Any

import structlog
from structlog.typing import EventDict, Processor, WrappedLogger

REDACTED = "[REDACTED]"

_SENSITIVE_KEY = re.compile(
    r"pass(word|wd)?|secret|token|authorization|cookie|api[_-]?key|credential|dsn|"
    r"database_url|redis_url|broker_url|private[_-]?key|session",
    re.IGNORECASE,
)
# Masks the password in URLs such as postgresql://user:password@host/db, which
# commonly appear inside exception messages and tracebacks.
_URL_CREDENTIALS = re.compile(r"(?P<prefix>[a-zA-Z][a-zA-Z0-9+.-]*://[^:/@\s]*:)[^@\s]+@")
_MAX_DEPTH = 6


def scrub_url_credentials(text: str) -> str:
    return _URL_CREDENTIALS.sub(rf"\g<prefix>{REDACTED}@", text)


def _redact(value: Any, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        return value
    if isinstance(value, Mapping):
        return {
            key: (
                REDACTED
                if isinstance(key, str) and _SENSITIVE_KEY.search(key)
                else _redact(item, depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        return type(value)(_redact(item, depth + 1) for item in value)
    if isinstance(value, str):
        return scrub_url_credentials(value)
    return value


def redact_sensitive_values(
    _logger: WrappedLogger, _method: str, event_dict: EventDict
) -> EventDict:
    """structlog processor that masks sensitive keys at any nesting level."""
    return {
        key: REDACTED if _SENSITIVE_KEY.search(key) else _redact(value)
        for key, value in event_dict.items()
    }


def configure_logging(*, level: str = "INFO", json_logs: bool = True) -> None:
    """Configure structlog and route stdlib logging (uvicorn, sqlalchemy) through it."""
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        redact_sensitive_values,
    ]

    renderer: Processor = (
        structlog.processors.JSONRenderer()
        if json_logs
        else structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())
    )

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.format_exc_info,
            redact_sensitive_values,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Uvicorn's access log would duplicate our request log and include query strings
    # (which may carry sensitive values). Request logging is done by our middleware.
    logging.getLogger("uvicorn.access").handlers.clear()
    logging.getLogger("uvicorn.access").propagate = False
    logging.getLogger("uvicorn.access").disabled = True
    for name in ("uvicorn", "uvicorn.error"):
        logging.getLogger(name).handlers.clear()
        logging.getLogger(name).propagate = True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    logger: structlog.stdlib.BoundLogger = structlog.stdlib.get_logger(name)
    return logger
