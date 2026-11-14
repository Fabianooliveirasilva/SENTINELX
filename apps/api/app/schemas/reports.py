"""Report schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ReportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: Literal["project", "scan"] = "project"
    scan_job_id: uuid.UUID | None = None
    format: Literal["pdf", "json"] = "pdf"
    title: str | None = Field(default=None, max_length=200)
    include_resolved: bool = False
    include_ai: bool = True
    include_evidence: bool = True


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    scope: Literal["project", "scan"]
    scan_job_id: uuid.UUID | None
    format: Literal["pdf", "json"]
    title: str
    parameters: dict[str, Any]
    status: Literal["pending", "running", "completed", "failed"]
    schema_version: str
    size_bytes: int | None
    sha256: str | None
    summary: dict[str, Any]
    error: str | None
    generated_by_email: str | None
    created_at: datetime
    completed_at: datetime | None
