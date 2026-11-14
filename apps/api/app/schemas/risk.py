"""Risk model and project posture schemas."""

from __future__ import annotations

from datetime import date
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.findings import FindingRead, RiskBand


class RiskModelRead(BaseModel):
    model_version: str
    weights: dict[str, float]
    defaults: dict[str, float]
    bounds: dict[str, dict[str, float]]
    bands: dict[str, float]
    formula: str


class RiskWeightsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    weights: dict[str, Any] = Field(
        description="Complete or partial weight set; omitted keys keep their defaults."
    )


class RiskWeightsResult(RiskModelRead):
    rescored: int


class PostureRead(BaseModel):
    score: float
    band: RiskBand
    active: int
    counts: dict[RiskBand, int]


class TrendPoint(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    day: date
    score: float
    band: RiskBand
    active: int


class ProjectRiskRead(BaseModel):
    model_version: str
    posture: PostureRead
    top_risks: list[FindingRead]
    trend: list[TrendPoint]
