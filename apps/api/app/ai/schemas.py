"""Structured output of every AI analysis.

The same schema is used for model output (structured outputs) and for the
deterministic fallback, so the UI and reports never need to know which produced
an analysis beyond the labelled provider.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

Basis = Literal[
    "confirmed_evidence",  # shown by evidence or a finding marked confirmed
    "scanner_hypothesis",  # reported by a scanner, not confirmed
    "external_intelligence",  # NVD, CISA KEV, FIRST EPSS
    "ai_recommendation",  # the model's own inference or advice
]
BASES: tuple[str, ...] = (
    "confirmed_evidence",
    "scanner_hypothesis",
    "external_intelligence",
    "ai_recommendation",
)
Priority = Literal["immediate", "short_term", "long_term"]
Confidence = Literal["low", "medium", "high"]


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str
    basis: Basis
    references: list[str]


class Section(BaseModel):
    model_config = ConfigDict(extra="forbid")

    heading: str
    claims: list[Claim]


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str
    priority: Priority
    rationale: str
    references: list[str]


class AnalysisOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str
    summary: str
    sections: list[Section]
    recommended_actions: list[Action]
    investigation_steps: list[str]
    limitations: list[str]
    confidence: Confidence
