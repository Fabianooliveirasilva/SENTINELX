"""Centralized error handling with a single, consistent error envelope.

Every error response has the shape::

    {"error": {"code": "...", "message": "...", "request_id": "...", "details": [...]}}

Internal exception messages are never returned to clients; unexpected errors
are logged server-side (with redaction) and surfaced as a generic 500 by
``RequestContextMiddleware``.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.schemas.common import ErrorBody, ErrorDetail, ErrorResponse

# HTTPStatus.UNPROCESSABLE_CONTENT only exists on Python >= 3.13.
_HTTP_422 = 422


class AppError(Exception):
    """Base class for expected, client-facing domain errors."""

    status_code: int = HTTPStatus.BAD_REQUEST
    code: str = "bad_request"

    def __init__(
        self,
        message: str,
        *,
        details: list[ErrorDetail] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or []
        self.headers = headers


class AuthenticationError(AppError):
    status_code = HTTPStatus.UNAUTHORIZED
    code = "not_authenticated"

    def __init__(self, message: str = "Authentication required.") -> None:
        super().__init__(message, headers={"WWW-Authenticate": "Bearer"})


class PermissionDeniedError(AppError):
    status_code = HTTPStatus.FORBIDDEN
    code = "permission_denied"

    def __init__(self, message: str = "You do not have permission to perform this action.") -> None:
        super().__init__(message)


class NotFoundError(AppError):
    status_code = HTTPStatus.NOT_FOUND
    code = "not_found"


class ConflictError(AppError):
    status_code = HTTPStatus.CONFLICT
    code = "conflict"


class InvalidRequestError(AppError):
    """A syntactically valid request that violates a business rule."""

    status_code = _HTTP_422
    code = "invalid_request"


class CsrfError(AppError):
    status_code = HTTPStatus.FORBIDDEN
    code = "csrf_failed"

    def __init__(self) -> None:
        super().__init__("CSRF validation failed.")


class RateLimitedError(AppError):
    status_code = HTTPStatus.TOO_MANY_REQUESTS
    code = "rate_limited"

    def __init__(self, retry_after_seconds: int) -> None:
        super().__init__(
            "Too many requests. Please try again later.",
            headers={"Retry-After": str(max(1, retry_after_seconds))},
        )


class QuotaExceededError(AppError):
    status_code = HTTPStatus.TOO_MANY_REQUESTS
    code = "quota_exceeded"


class ServiceUnavailableError(AppError):
    status_code = HTTPStatus.SERVICE_UNAVAILABLE
    code = "service_unavailable"


def _request_id(request: Request) -> str | None:
    value = getattr(request.state, "request_id", None)
    return value if isinstance(value, str) else None


def _status_code_slug(status_code: int) -> str:
    try:
        return HTTPStatus(status_code).phrase.lower().replace(" ", "_").replace("-", "_")
    except ValueError:
        return "error"


def error_response(
    request: Request,
    *,
    status_code: int,
    code: str,
    message: str,
    details: list[ErrorDetail] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    body = ErrorResponse(
        error=ErrorBody(
            code=code,
            message=message,
            request_id=_request_id(request),
            details=details or [],
        )
    )
    return JSONResponse(
        status_code=status_code,
        content=body.model_dump(mode="json"),
        headers=headers,
    )


async def _handle_app_error(request: Request, exc: AppError) -> JSONResponse:
    return error_response(
        request,
        status_code=exc.status_code,
        code=exc.code,
        message=exc.message,
        details=exc.details,
        headers=exc.headers,
    )


async def _handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    message = exc.detail if isinstance(exc.detail, str) else HTTPStatus(exc.status_code).phrase
    return error_response(
        request,
        status_code=exc.status_code,
        code=_status_code_slug(exc.status_code),
        message=message,
        headers=dict(exc.headers) if exc.headers else None,
    )


async def _handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    # The submitted input is intentionally NOT echoed back (it may contain secrets).
    details = [
        ErrorDetail(
            location=[str(part) for part in error.get("loc", ())],
            message=str(error.get("msg", "invalid value")),
            type=str(error.get("type", "value_error")),
        )
        for error in exc.errors()
    ]
    return error_response(
        request,
        status_code=_HTTP_422,
        code="validation_error",
        message="The request payload is invalid.",
        details=details,
    )


def internal_error_response(request_id: str | None) -> JSONResponse:
    """Generic 500 used for unhandled exceptions; never includes exception details."""
    body = ErrorResponse(
        error=ErrorBody(
            code="internal_error",
            message="An unexpected error occurred.",
            request_id=request_id,
        )
    )
    return JSONResponse(
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR, content=body.model_dump(mode="json")
    )


def register_exception_handlers(app: FastAPI) -> None:
    handlers: dict[Any, Any] = {
        AppError: _handle_app_error,
        StarletteHTTPException: _handle_http_exception,
        RequestValidationError: _handle_validation_error,
    }
    # Unhandled exceptions are converted to a generic 500 by RequestContextMiddleware,
    # which runs inside the security-headers middleware so the response stays hardened.
    for exc_class, handler in handlers.items():
        app.add_exception_handler(exc_class, handler)
