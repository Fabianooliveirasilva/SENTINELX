"""Asset inventory, authorization records and scope checks.

Every operation is scoped to a project the caller can see (non-members get 404).
Authorizations are immutable records; the only permitted change is revocation,
so the history of who authorized what, when and for which techniques is preserved.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.core.context import Principal, RequestMeta
from app.core.errors import (
    ConflictError,
    InvalidRequestError,
    NotFoundError,
    PermissionDeniedError,
)
from app.models import Asset, AssetAuthorization, AuditLog
from app.repositories.sql import LIKE_ESCAPE, contains_pattern
from app.schemas.pagination import PageParams
from app.services.audit import record_audit
from app.services.projects import ProjectService
from app.services.risk import rescore, snapshot
from sentinelx_security.scope import (
    AssetType,
    AuthorizationGrant,
    ScopeAsset,
    ScopeDecision,
    ScopeEngine,
    TargetError,
    Technique,
    normalize_asset_value,
)
from sentinelx_security.scope.network_policy import IPNetwork

# Broad ranges would effectively authorize unrelated third parties.
MIN_IPV4_PREFIX: Final = 16
MIN_IPV6_PREFIX: Final = 48
MAX_IP_RANGES: Final = 50


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class AssetFilters:
    type: AssetType | None = None
    status: str | None = None
    criticality: str | None = None
    tag: str | None = None
    search: str | None = None


@dataclass(frozen=True, slots=True)
class NewAuthorization:
    authorized_by: str
    organization: str
    reference: str
    notes: str
    valid_from: datetime
    valid_until: datetime
    allow_active: bool
    allow_intrusive: bool
    include_subdomains: bool
    ip_ranges: Sequence[str]


@dataclass(frozen=True, slots=True)
class Eligibility:
    passive: bool
    active: bool
    intrusive: bool
    reasons: tuple[str, ...]


def authorization_status(auth: AssetAuthorization, now: datetime) -> str:
    if auth.revoked_at is not None:
        return "revoked"
    if now < auth.valid_from:
        return "scheduled"
    if now >= auth.valid_until:
        return "expired"
    return "active"


def to_grant(auth: AssetAuthorization) -> AuthorizationGrant:
    return AuthorizationGrant(
        id=auth.id,
        valid_from=auth.valid_from,
        valid_until=auth.valid_until,
        revoked=auth.revoked_at is not None,
        allow_active=auth.allow_active,
        allow_intrusive=auth.allow_intrusive,
        include_subdomains=auth.include_subdomains,
        ip_ranges=tuple(ipaddress.ip_network(r) for r in auth.ip_ranges),
    )


def to_scope_asset(asset: Asset) -> ScopeAsset:
    return ScopeAsset(
        id=asset.id,
        type=AssetType(asset.type),
        value=asset.value,
        active=asset.status == "active",
        authorizations=tuple(to_grant(a) for a in asset.authorizations),
    )


def compute_eligibility(asset: Asset, engine: ScopeEngine, now: datetime) -> Eligibility:
    """Static eligibility (no DNS). Resolved addresses are validated at scan time."""
    reasons: list[str] = []
    if asset.status != "active":
        return Eligibility(False, False, False, ("Asset is archived.",))
    current = [g for g in (to_grant(a) for a in asset.authorizations) if g.is_current(now)]
    if not current:
        reasons.append("No authorization is valid right now.")
    passive = bool(current)
    active = any(g.permits(Technique.ACTIVE) for g in current)
    intrusive = any(g.permits(Technique.INTRUSIVE) for g in current)
    if passive and not active:
        reasons.append("Current authorizations permit passive techniques only.")
    if active and asset.type != AssetType.IP_ADDRESS.value:
        reasons.append("Active testing also requires every resolved address to be authorized.")
    problem = engine.registration_problem(AssetType(asset.type), asset.value)
    if problem is not None:
        return Eligibility(False, False, False, (problem.message,))
    return Eligibility(passive, active, intrusive, tuple(reasons))


def _parse_ranges(values: Sequence[str], engine: ScopeEngine) -> list[str]:
    if len(values) > MAX_IP_RANGES:
        raise InvalidRequestError(f"At most {MAX_IP_RANGES} IP ranges are allowed.")
    ranges: list[str] = []
    for value in values:
        try:
            network: IPNetwork = ipaddress.ip_network(value.strip(), strict=True)
        except ValueError as exc:
            raise InvalidRequestError(f"{value!r} is not a valid network (CIDR).") from exc
        minimum = MIN_IPV4_PREFIX if network.version == 4 else MIN_IPV6_PREFIX
        if network.prefixlen < minimum:
            raise InvalidRequestError(
                f"{network} is too broad; the minimum prefix is "
                f"/{minimum} for IPv{network.version}."
            )
        lab = all(
            engine.policy.in_lab(a) for a in (network.network_address, network.broadcast_address)
        )
        if not lab and not network.is_global:
            raise InvalidRequestError(
                f"{network} is not publicly routable and is not inside a configured lab network."
            )
        ranges.append(str(network))
    return sorted(set(ranges))


class AssetService:
    def __init__(self, session: AsyncSession, engine: ScopeEngine, settings: Settings) -> None:
        self._session = session
        self._engine = engine
        self._settings = settings
        self._projects = ProjectService(session)

    # ------------------------------------------------------------------ queries

    async def list(
        self, principal: Principal, project_id: uuid.UUID, params: PageParams, filters: AssetFilters
    ) -> tuple[Sequence[Asset], int]:
        await self._projects.get(principal, project_id)
        stmt = select(Asset).where(Asset.project_id == project_id)
        if filters.type is not None:
            stmt = stmt.where(Asset.type == filters.type.value)
        if filters.status:
            stmt = stmt.where(Asset.status == filters.status)
        if filters.criticality:
            stmt = stmt.where(Asset.criticality == filters.criticality)
        if filters.tag:
            stmt = stmt.where(Asset.tags.contains([filters.tag.strip().lower()]))
        if filters.search:
            stmt = stmt.where(
                Asset.value.like(contains_pattern(filters.search), escape=LIKE_ESCAPE)
            )
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )
        rows = (
            (
                await self._session.execute(
                    stmt.order_by(Asset.type, Asset.value)
                    .offset(params.offset)
                    .limit(params.page_size)
                )
            )
            .scalars()
            .all()
        )
        return rows, total

    async def get(self, principal: Principal, project_id: uuid.UUID, asset_id: uuid.UUID) -> Asset:
        await self._projects.get(principal, project_id)
        asset = (
            await self._session.execute(
                select(Asset)
                .where(Asset.id == asset_id, Asset.project_id == project_id)
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if asset is None:
            raise NotFoundError("Asset not found.")
        return asset

    async def history(
        self, principal: Principal, project_id: uuid.UUID, asset_id: uuid.UUID
    ) -> Sequence[AuditLog]:
        asset = await self.get(principal, project_id, asset_id)
        stmt = (
            select(AuditLog)
            .where(AuditLog.target_type == "asset", AuditLog.target_id == str(asset.id))
            .order_by(AuditLog.created_at.desc())
            .limit(200)
        )
        return (await self._session.execute(stmt)).scalars().all()

    def eligibility(self, asset: Asset, now: datetime | None = None) -> Eligibility:
        return compute_eligibility(asset, self._engine, now or utcnow())

    async def scope_check(
        self, principal: Principal, project_id: uuid.UUID, target: str, technique: Technique
    ) -> ScopeDecision:
        await self._projects.get(principal, project_id)
        assets = (
            (await self._session.execute(select(Asset).where(Asset.project_id == project_id)))
            .scalars()
            .all()
        )
        return await self._engine.evaluate(
            target, technique, [to_scope_asset(a) for a in assets], utcnow()
        )

    # ------------------------------------------------------------------ commands

    async def create(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        *,
        asset_type: AssetType,
        value: str,
        description: str,
        tags: Sequence[str],
        criticality: str,
        exposure: str,
        meta: RequestMeta,
    ) -> Asset:
        await self._projects.get(principal, project_id)
        try:
            normalized = normalize_asset_value(asset_type, value)
        except TargetError as exc:
            raise InvalidRequestError(exc.message) from exc
        problem = self._engine.registration_problem(asset_type, normalized)
        if problem is not None:
            raise InvalidRequestError(problem.message)

        asset = Asset(
            project_id=project_id,
            type=asset_type.value,
            value=normalized,
            description=description.strip(),
            tags=sorted({t.strip().lower() for t in tags if t.strip()}),
            criticality=criticality,
            exposure=exposure,
            created_by_id=principal.user_id,
        )
        self._session.add(asset)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            raise ConflictError("This asset is already registered in the project.") from exc
        record_audit(
            self._session,
            action="asset.created",
            actor=principal.actor,
            meta=meta,
            target_type="asset",
            target_id=asset.id,
            project_id=project_id,
            details={"type": asset.type, "value": asset.value},
        )
        await self._session.commit()
        return await self.get(principal, project_id, asset.id)

    async def update(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        asset_id: uuid.UUID,
        changes: dict[str, object],
        meta: RequestMeta,
    ) -> Asset:
        asset = await self.get(principal, project_id, asset_id)
        changed: dict[str, object] = {}
        for field_name, new_value in changes.items():
            value = new_value
            if field_name == "description" and isinstance(value, str):
                value = value.strip()
            if field_name == "tags" and isinstance(value, list):
                value = sorted({str(t).strip().lower() for t in value if str(t).strip()})
            if getattr(asset, field_name) != value:
                setattr(asset, field_name, value)
                changed[field_name] = value if field_name != "description" else True
        if changed:
            action = "asset.updated"
            if changed.get("status") == "archived":
                action = "asset.archived"
            elif changed.get("status") == "active":
                action = "asset.restored"
            record_audit(
                self._session,
                action=action,
                actor=principal.actor,
                meta=meta,
                target_type="asset",
                target_id=asset.id,
                project_id=project_id,
                details={"changes": changed},
            )
        if {"criticality", "exposure"} & set(changed):
            await rescore(self._session, trigger="asset_updated", asset_id=asset.id)
            await snapshot(self._session, project_id)
        await self._session.commit()
        return await self.get(principal, project_id, asset.id)

    async def add_authorization(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        asset_id: uuid.UUID,
        data: NewAuthorization,
        meta: RequestMeta,
    ) -> AssetAuthorization:
        asset = await self.get(principal, project_id, asset_id)
        now = utcnow()
        if asset.status != "active":
            raise InvalidRequestError("Archived assets cannot receive new authorizations.")
        if data.allow_intrusive and not principal.is_admin:
            raise PermissionDeniedError("Only administrators can authorize intrusive testing.")
        if data.allow_intrusive and not data.allow_active:
            raise InvalidRequestError(
                "Intrusive testing also requires active testing to be allowed."
            )
        if data.valid_until <= data.valid_from:
            raise InvalidRequestError("The authorization must end after it starts.")
        if data.valid_until <= now:
            raise InvalidRequestError("The authorization window has already ended.")
        if data.valid_until - data.valid_from > timedelta(
            days=self._settings.max_authorization_days
        ):
            raise InvalidRequestError(
                f"Authorizations may last at most {self._settings.max_authorization_days} days."
            )
        if data.include_subdomains and asset.type not in (AssetType.DOMAIN, AssetType.SUBDOMAIN):
            raise InvalidRequestError("Subdomain coverage only applies to domain assets.")

        authorization = AssetAuthorization(
            asset_id=asset.id,
            project_id=project_id,
            authorized_by=data.authorized_by.strip(),
            organization=data.organization.strip(),
            reference=data.reference.strip(),
            notes=data.notes.strip(),
            valid_from=data.valid_from,
            valid_until=data.valid_until,
            allow_active=data.allow_active,
            allow_intrusive=data.allow_intrusive,
            include_subdomains=data.include_subdomains,
            ip_ranges=_parse_ranges(data.ip_ranges, self._engine),
            recorded_by_id=principal.user_id,
        )
        self._session.add(authorization)
        await self._session.flush()
        record_audit(
            self._session,
            action="asset.authorization_added",
            actor=principal.actor,
            meta=meta,
            target_type="asset",
            target_id=asset.id,
            project_id=project_id,
            details={
                "authorization_id": str(authorization.id),
                "reference": authorization.reference,
                "valid_from": authorization.valid_from.isoformat(),
                "valid_until": authorization.valid_until.isoformat(),
                "allow_active": authorization.allow_active,
                "allow_intrusive": authorization.allow_intrusive,
                "include_subdomains": authorization.include_subdomains,
                "ip_ranges": authorization.ip_ranges,
            },
        )
        await self._session.commit()
        await self._session.refresh(authorization)
        return authorization

    async def revoke_authorization(
        self,
        principal: Principal,
        project_id: uuid.UUID,
        asset_id: uuid.UUID,
        authorization_id: uuid.UUID,
        reason: str,
        meta: RequestMeta,
    ) -> AssetAuthorization:
        asset = await self.get(principal, project_id, asset_id)
        authorization = next((a for a in asset.authorizations if a.id == authorization_id), None)
        if authorization is None:
            raise NotFoundError("Authorization not found.")
        if authorization.revoked_at is not None:
            raise ConflictError("This authorization is already revoked.")
        authorization.revoked_at = utcnow()
        authorization.revoked_by_id = principal.user_id
        authorization.revocation_reason = reason.strip()
        record_audit(
            self._session,
            action="asset.authorization_revoked",
            actor=principal.actor,
            meta=meta,
            target_type="asset",
            target_id=asset.id,
            project_id=project_id,
            details={"authorization_id": str(authorization.id), "reason": reason.strip()},
        )
        await self._session.commit()
        await self._session.refresh(authorization)
        return authorization
