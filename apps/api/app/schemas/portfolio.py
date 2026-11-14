"""Cross-project views: vulnerability list and reconnaissance overview."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from app.schemas.findings import FindingStatus, RiskBand, Severity


class PortfolioFinding(BaseModel):
    id: str
    project_id: str
    project_name: str
    asset: str
    title: str
    severity: Severity
    status: FindingStatus
    source: str
    risk_band: RiskBand | None
    risk_score: float | None
    cve_id: str | None
    first_seen_at: datetime
    last_seen_at: datetime


class PortfolioFindingsPage(BaseModel):
    items: list[PortfolioFinding]
    total: int
    page: int
    page_size: int
    by_severity: dict[str, int]


class ReconAsset(BaseModel):
    id: str
    project_id: str
    project_name: str
    type: str
    value: str
    exposure: str
    created_at: datetime


class ReconScan(BaseModel):
    id: str
    project_id: str
    project_name: str
    scanner: str
    profile: str
    target: str
    status: str
    created_at: datetime
    finished_at: datetime | None


class ReconOverview(BaseModel):
    generated_at: datetime
    projects: int
    assets_total: int
    assets_new_7d: int
    assets_by_type: dict[str, int]
    assets_by_exposure: dict[str, int]
    scans_30d_by_scanner: dict[str, int]
    scans_30d_by_status: dict[str, int]
    recent_assets: list[ReconAsset]
    recent_scans: list[ReconScan]
    empty: bool
