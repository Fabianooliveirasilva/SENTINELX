"""Scan job schemas.

Observation data and evidence come from scanned systems and are untrusted: the
API returns them as plain JSON/text and the UI renders them as text only.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.models import ScanEvidence, ScanJob, ScanResult
from app.services.scans import ScanControls
from sentinelx_security.scanners import CATALOG
from sentinelx_security.scope import AssetType, Technique

ScanStatus = Literal["pending", "queued", "running", "completed", "failed", "cancelled"]
ScannerId = Annotated[str, StringConstraints(pattern=r"^[a-z]{2,32}$")]
ProfileId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_]{1,32}$")]


class ScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: uuid.UUID
    scanner: ScannerId
    profile: ProfileId | None = Field(
        default=None, description="Server-side profile name; the scanner default when omitted."
    )


class ScanProfileRead(BaseModel):
    name: str
    description: str
    technique: Technique


class ScannerRead(BaseModel):
    name: str
    technique: Technique
    description: str
    default_profile: str
    profiles: list[ScanProfileRead]
    supported_asset_types: list[AssetType]


def scanner_catalog() -> list[ScannerRead]:
    return [
        ScannerRead(
            name=cls.name.value,
            technique=cls.technique,
            description=cls.description,
            default_profile=cls.default_profile,
            profiles=[
                ScanProfileRead(name=k, description=v, technique=cls.technique_for(k))
                for k, v in cls.profiles.items()
            ],
            supported_asset_types=sorted(cls.supported_asset_types),
        )
        for cls in CATALOG.values()
    ]


class ScanJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    asset_id: uuid.UUID
    scanner: str
    profile: str
    technique: Technique
    target: str
    status: ScanStatus
    requested_by_id: uuid.UUID | None
    created_at: datetime
    queued_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    error_code: str | None
    error_message: str | None
    pinned_addresses: list[str]
    summary: dict[str, Any]


class ScanResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    kind: str
    key: str
    data: dict[str, Any]
    attention: list[str]


class ScanEvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    label: str
    media_type: str
    content: str


class ScanJobDetail(ScanJobRead):
    scope_decision: dict[str, Any] | None
    tool_versions: dict[str, str]
    correlation_id: str | None
    results: list[ScanResultRead]
    evidence: list[ScanEvidenceRead]

    @classmethod
    def from_model(cls, job: ScanJob) -> ScanJobDetail:
        base = ScanJobRead.model_validate(job).model_dump()
        results: list[ScanResult] = job.results
        evidence: list[ScanEvidence] = job.evidence
        return cls(
            **base,
            scope_decision=job.scope_decision,
            tool_versions=job.tool_versions,
            correlation_id=job.correlation_id,
            results=[ScanResultRead.model_validate(r) for r in results],
            evidence=[ScanEvidenceRead.model_validate(e) for e in evidence],
        )


class ScanControlsRead(BaseModel):
    halted: bool
    reason: str | None
    updated_at: datetime | None
    updated_by: str | None

    @classmethod
    def from_domain(cls, controls: ScanControls) -> ScanControlsRead:
        return cls(
            halted=controls.halted,
            reason=controls.reason,
            updated_at=controls.updated_at,
            updated_by=controls.updated_by,
        )


class EmergencyStopRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=500)]


class EmergencyStopResult(ScanControlsRead):
    cancelled_jobs: int
