"""Asset, authorization and scope-check schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
)

from app.models import Asset, AssetAuthorization
from app.services.assets import Eligibility, authorization_status
from sentinelx_security.scope import AssetType, ScopeDecision, Technique

Criticality = Literal["low", "medium", "high", "critical"]
Exposure = Literal["external", "internal", "unknown"]
AssetStatus = Literal["active", "archived"]


def _normalize_tag(value: object) -> object:
    return value.strip().lower() if isinstance(value, str) else value


Tag = Annotated[
    str,
    BeforeValidator(_normalize_tag),
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9_.:-]{0,49}$"),
]
ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]


class AssetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: AssetType
    value: Annotated[str, Field(min_length=1, max_length=2048)]
    description: Annotated[str, Field(max_length=2000)] = ""
    tags: Annotated[list[Tag], Field(max_length=20)] = Field(default_factory=list)
    criticality: Criticality = "medium"
    exposure: Exposure = "external"


class AssetUpdate(BaseModel):
    """Type and value are immutable; register a new asset instead."""

    model_config = ConfigDict(extra="forbid")

    description: Annotated[str, Field(max_length=2000)] | None = None
    tags: Annotated[list[Tag], Field(max_length=20)] | None = None
    criticality: Criticality | None = None
    exposure: Exposure | None = None
    status: AssetStatus | None = None


class EligibilityRead(BaseModel):
    passive: bool
    active: bool
    intrusive: bool
    reasons: list[str]

    @classmethod
    def from_domain(cls, eligibility: Eligibility) -> EligibilityRead:
        return cls(
            passive=eligibility.passive,
            active=eligibility.active,
            intrusive=eligibility.intrusive,
            reasons=list(eligibility.reasons),
        )


class AuthorizationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authorized_by: ShortText = Field(description="Person who granted permission.")
    organization: ShortText = Field(description="Organization that owns the asset.")
    reference: ShortText = Field(description="Contract, ticket or engagement reference.")
    notes: Annotated[str, Field(max_length=4000)] = ""
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    allow_active: bool = False
    allow_intrusive: bool = False
    include_subdomains: bool = False
    ip_ranges: Annotated[list[Annotated[str, Field(max_length=64)]], Field(max_length=50)] = Field(
        default_factory=list, description="CIDR ranges whose addresses may be actively tested."
    )


class AuthorizationRead(BaseModel):
    id: uuid.UUID
    authorized_by: str
    organization: str
    reference: str
    notes: str
    valid_from: datetime
    valid_until: datetime
    allow_active: bool
    allow_intrusive: bool
    include_subdomains: bool
    ip_ranges: list[str]
    status: Literal["active", "scheduled", "expired", "revoked"]
    recorded_by_id: uuid.UUID | None
    created_at: datetime
    revoked_at: datetime | None
    revocation_reason: str | None

    @classmethod
    def from_model(cls, auth: AssetAuthorization, *, now: datetime) -> AuthorizationRead:
        return cls(
            id=auth.id,
            authorized_by=auth.authorized_by,
            organization=auth.organization,
            reference=auth.reference,
            notes=auth.notes,
            valid_from=auth.valid_from,
            valid_until=auth.valid_until,
            allow_active=auth.allow_active,
            allow_intrusive=auth.allow_intrusive,
            include_subdomains=auth.include_subdomains,
            ip_ranges=list(auth.ip_ranges),
            status=authorization_status(auth, now),  # type: ignore[arg-type]
            recorded_by_id=auth.recorded_by_id,
            created_at=auth.created_at,
            revoked_at=auth.revoked_at,
            revocation_reason=auth.revocation_reason,
        )


class RevokeAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=500)]


class AssetRead(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    type: AssetType
    value: str
    description: str
    tags: list[str]
    criticality: Criticality
    exposure: Exposure
    status: AssetStatus
    created_at: datetime
    updated_at: datetime
    eligibility: EligibilityRead
    active_authorizations: int

    @classmethod
    def from_model(cls, asset: Asset, eligibility: Eligibility, *, now: datetime) -> AssetRead:
        return cls(
            id=asset.id,
            project_id=asset.project_id,
            type=AssetType(asset.type),
            value=asset.value,
            description=asset.description,
            tags=list(asset.tags),
            criticality=asset.criticality,  # type: ignore[arg-type]
            exposure=asset.exposure,  # type: ignore[arg-type]
            status=asset.status,  # type: ignore[arg-type]
            created_at=asset.created_at,
            updated_at=asset.updated_at,
            eligibility=EligibilityRead.from_domain(eligibility),
            active_authorizations=sum(
                1 for a in asset.authorizations if authorization_status(a, now) == "active"
            ),
        )


class AssetDetail(AssetRead):
    authorizations: list[AuthorizationRead]


class ScopeCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: Annotated[str, Field(min_length=1, max_length=2048)]
    technique: Technique = Technique.ACTIVE


class AddressVerdictRead(BaseModel):
    address: str
    allowed: bool
    reason: str | None


class ReasonRead(BaseModel):
    code: str
    message: str


class ScopeDecisionRead(BaseModel):
    allowed: bool
    target: str
    technique: Technique
    asset_id: uuid.UUID | None
    authorization_id: uuid.UUID | None
    addresses: list[AddressVerdictRead]
    reasons: list[ReasonRead]

    @classmethod
    def from_domain(cls, decision: ScopeDecision) -> ScopeDecisionRead:
        return cls(
            allowed=decision.allowed,
            target=decision.target,
            technique=decision.technique,
            asset_id=decision.asset_id,
            authorization_id=decision.authorization_id,
            addresses=[
                AddressVerdictRead(address=v.address, allowed=v.allowed, reason=v.reason)
                for v in decision.addresses
            ],
            reasons=[ReasonRead(code=r.code, message=r.message) for r in decision.reasons],
        )
