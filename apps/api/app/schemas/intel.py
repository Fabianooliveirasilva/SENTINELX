"""Threat-intelligence schemas."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

CpeName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.\-!\\]{1,100}$", to_lower=True)]


class CveRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    source: str
    description: str
    status: str
    published_at: datetime | None
    last_modified_at: datetime | None
    cvss_version: str | None
    cvss_vector: str | None
    cvss_score: float | None
    cvss_severity: str | None
    cwes: list[str]
    kev_added_on: date | None
    fetched_at: datetime


class CveMatchRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    criteria: str
    vendor: str
    product: str
    version: str
    start_including: str | None
    start_excluding: str | None
    end_including: str | None
    end_excluding: str | None


class CveDetail(CveRead):
    cvss31_vector: str | None
    cvss31_score: float | None
    cvss40_vector: str | None
    cvss40_score: float | None
    references: list[str]
    kev_due_on: date | None
    kev_ransomware: str | None
    matches: list[CveMatchRead]


class IntelSourceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    synced_at: datetime | None
    status: str
    version: str | None
    records: int
    error: str | None


class ProductSyncRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    vendor: str
    product: str
    requested_at: datetime
    synced_at: datetime | None
    status: str
    cve_count: int
    error: str | None


class IntelStatus(BaseModel):
    enabled: bool
    nvd_api_key_configured: bool
    cves: int
    kev_cves: int
    sources: list[IntelSourceRead]
    products: list[ProductSyncRead]


class ProductSyncRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vendor: CpeName
    product: CpeName


class SoftwareComponentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    source: str
    name: str
    version: str
    raw_version: str
    cpes: list[str]
    location: str
    correlatable: bool
    last_seen_at: datetime
    last_scan_job_id: uuid.UUID | None
