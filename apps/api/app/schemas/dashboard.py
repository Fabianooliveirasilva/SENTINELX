"""Dashboard schema: every figure is computed from stored data."""

from __future__ import annotations

from pydantic import BaseModel

from app.schemas.findings import Severity


class DashboardScope(BaseModel):
    project_id: str | None
    projects: int


class DashboardTotals(BaseModel):
    assets: int
    active_scans: int
    active_findings: int
    critical_findings: int
    high_findings: int
    known_exploited_findings: int


class ProjectRef(BaseModel):
    id: str
    name: str


class DashboardPosture(BaseModel):
    score: float
    band: Severity
    worst_project: ProjectRef | None


class TrendPoint(BaseModel):
    day: str
    score: float


class ActivityDay(BaseModel):
    day: str
    completed: int
    failed: int
    cancelled: int
    active: int


class RemediationWeek(BaseModel):
    week: str
    opened: int
    resolved: int


class Remediation(BaseModel):
    weekly: list[RemediationWeek]
    by_status: dict[str, int]
    closed_ratio: float | None


class RecentFinding(BaseModel):
    id: str
    project_id: str
    project_name: str
    title: str
    severity: Severity
    risk_band: Severity | None
    risk_score: float | None
    asset: str
    first_seen_at: str


class ProjectPosture(BaseModel):
    id: str
    name: str
    score: float
    band: Severity
    active: int


class DashboardRead(BaseModel):
    generated_at: str
    scope: DashboardScope
    totals: DashboardTotals
    posture: DashboardPosture
    posture_trend: list[TrendPoint]
    risk_distribution: dict[Severity, int]
    assets_by_exposure: dict[str, int]
    scan_activity: list[ActivityDay]
    remediation: Remediation
    recent_findings: list[RecentFinding]
    projects: list[ProjectPosture]
    empty: bool
