"""Finding schemas. Descriptions and observations may contain scanner-supplied text."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["tentative", "firm", "confirmed"]
RiskBand = Literal["info", "low", "medium", "high", "critical"]
FindingSort = Literal["risk", "severity", "last_seen"]
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
    cve_id: str | None
    risk_score: float | None
    risk_band: RiskBand | None


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


class RiskFactorRead(BaseModel):
    name: str
    value: str
    effect: str
    points: float
    reason: str


class RiskChangeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    score: float
    band: RiskBand
    model_version: str
    trigger: str
    calculated_at: datetime


class FindingDetail(FindingRead):
    description: str
    remediation: str
    references: list[str]
    ruleset_version: str
    occurrences: list[FindingOccurrenceRead]
    history: list[FindingStatusChangeRead]
    risk_factors: list[RiskFactorRead]
    risk_explanation: str | None
    risk_model_version: str | None
    risk_calculated_at: datetime | None
    risk_history: list[RiskChangeRead]


class FindingStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: FindingStatus
    reason: Annotated[str, StringConstraints(strip_whitespace=True, max_length=2000)] = ""


class FindingSummary(BaseModel):
    by_status: dict[FindingStatus, int]
    active_by_severity: dict[Severity, int]
