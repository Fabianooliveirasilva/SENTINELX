"""AI analyst schemas. Outputs are advisory and always labelled with their provider."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

AnalysisKind = Literal[
    "finding_analysis",
    "scan_summary",
    "scan_comparison",
    "executive_summary",
    "technical_summary",
]


class AnalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: AnalysisKind
    subject_id: uuid.UUID | None = None
    compare_with: uuid.UUID | None = None
    refresh: bool = False


class AnalysisRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    kind: AnalysisKind
    subject_type: str
    subject_id: uuid.UUID
    parameters: dict[str, Any]
    status: Literal["pending", "running", "completed", "failed"]
    provider: Literal["anthropic", "deterministic"] | None
    model: str | None
    prompt_version: str
    context_summary: dict[str, Any]
    output: dict[str, Any] | None
    warnings: list[str]
    fallback_reason: str | None
    error: str | None
    input_tokens: int
    output_tokens: int
    cost_usd: float
    duration_ms: int | None
    requested_by_id: uuid.UUID | None
    reviewed_by_email: str | None
    reviewed_at: datetime | None
    created_at: datetime
    completed_at: datetime | None


class AIUsageRead(BaseModel):
    enabled: bool
    model: str | None
    tokens_today: int
    cost_today_usd: float
    daily_token_budget: int
