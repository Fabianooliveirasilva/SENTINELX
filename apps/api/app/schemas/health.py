"""Health check response schemas."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class ComponentStatus(StrEnum):
    OK = "ok"
    UNAVAILABLE = "unavailable"


class LivenessReport(BaseModel):
    status: Literal["ok"] = "ok"


class ComponentHealth(BaseModel):
    status: ComponentStatus
    latency_ms: float | None = Field(default=None, ge=0)
    error: Literal["timeout", "unreachable"] | None = None


class ReadinessReport(BaseModel):
    status: ComponentStatus
    version: str
    components: dict[str, ComponentHealth]
