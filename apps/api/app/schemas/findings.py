"""Finding schemas. Descriptions and observations may contain scanner-supplied text."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["tentative", "firm", "confirmed"]
FindingStatus = Literal["open", "acknowledged", "false_positive", "accepted_risk", "resolved"]


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    asset_id: uuid.UUID
    rule_id: str
    source: str
    category: str
    title: str
    location: str
    severity: Severity
    confidence: Confidence
    cwe: int | None
    status: FindingStatus
    status_reason: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None
    occurrence_count: int
    last_scan_job_id: uuid.UUID | None


class FindingOccurrenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_job_id: uuid.UUID | None
    observed_at: datetime
    observation: dict[str, Any]


class FindingStatusChangeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    from_status: FindingStatus | None
    to_status: FindingStatus
    reason: str
    changed_by_email: str | None
    created_at: datetime


class FindingDetail(FindingRead):
    description: str
    remediation: str
    references: list[str]
    ruleset_version: str
    occurrences: list[FindingOccurrenceRead]
    history: list[FindingStatusChangeRead]


class FindingStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: FindingStatus
    reason: Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000)] = ""


class FindingSummary(BaseModel):
    by_status: dict[FindingStatus, int]
    active_by_severity: dict[Severity, int]
