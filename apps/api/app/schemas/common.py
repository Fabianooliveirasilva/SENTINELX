"""Schemas shared across API resources."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ErrorDetail(BaseModel):
    model_config = ConfigDict(frozen=True)

    location: list[str] = Field(default_factory=list, description="Path to the offending field.")
    message: str
    type: str


class ErrorBody(BaseModel):
    code: str = Field(description="Stable, machine-readable error code.")
    message: str = Field(description="Human-readable summary safe to display.")
    request_id: str | None = Field(description="Correlation ID for support and log lookup.")
    details: list[ErrorDetail] = Field(default_factory=list)


class ErrorResponse(BaseModel):
    error: ErrorBody


def error_responses(*status_codes: int) -> dict[int | str, dict[str, Any]]:
    """OpenAPI ``responses`` entries documenting the error envelope."""
    return {code: {"model": ErrorResponse} for code in status_codes}
