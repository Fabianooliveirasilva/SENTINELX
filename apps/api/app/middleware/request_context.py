"""Request correlation and access logging (pure ASGI middleware).

* Accepts an inbound ``X-Request-ID`` only when it matches a strict pattern,
  otherwise generates a new one (prevents log injection / header smuggling).
* Binds the ID to the logging context so every log line for the request
  carries it, exposes it on ``request.state.request_id`` and echoes it in the
  response header so clients and background jobs can be correlated.
* Converts unhandled exceptions into a generic 500 error envelope (the
  exception is logged server-side, never returned to the client).
* Emits one structured access-log line per request with latency. Query strings
  are intentionally not logged because they may contain sensitive values.
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Final

import structlog
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import internal_error_response
from app.core.logging import get_logger

REQUEST_ID_HEADER: Final = "X-Request-ID"
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")

logger = get_logger("sentinelx.access")


def resolve_request_id(candidate: str | None) -> str:
    if candidate and _VALID_REQUEST_ID.fullmatch(candidate):
        return candidate
    return str(uuid.uuid4())


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = resolve_request_id(Headers(scope=scope).get(REQUEST_ID_HEADER))
        scope.setdefault("state", {})["request_id"] = request_id

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        started = time.perf_counter()
        status_code = 500
        response_started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code, response_started
            if message["type"] == "http.response.start":
                response_started = True
                status_code = message["status"]
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:
            logger.error(
                "unhandled_exception",
                exc_type=type(exc).__name__,
                path=scope.get("path"),
                exc_info=exc,
            )
            if response_started:
                raise
            await internal_error_response(request_id)(scope, receive, send_wrapper)
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            log = logger.warning if status_code >= 500 else logger.info
            log(
                "http_request",
                method=scope.get("method"),
                path=scope.get("path"),
                status_code=status_code,
                duration_ms=duration_ms,
            )
            structlog.contextvars.clear_contextvars()
