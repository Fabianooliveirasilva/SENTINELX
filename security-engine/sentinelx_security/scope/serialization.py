"""JSON-safe (de)serialization of scope inputs and decisions.

Scope data crosses the broker between the orchestrator (which has database
access) and the scanner worker (which has none), so it must round-trip through
JSON exactly. Celery is configured for JSON only; never pickle.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Any

from sentinelx_security.scope.engine import (
    AssetType,
    AuthorizationGrant,
    Reason,
    ScopeAsset,
    ScopeDecision,
    Technique,
)
from sentinelx_security.scope.network_policy import AddressVerdict


def grant_to_dict(grant: AuthorizationGrant) -> dict[str, Any]:
    return {
        "id": str(grant.id),
        "valid_from": grant.valid_from.isoformat(),
        "valid_until": grant.valid_until.isoformat(),
        "revoked": grant.revoked,
        "allow_active": grant.allow_active,
        "allow_intrusive": grant.allow_intrusive,
        "include_subdomains": grant.include_subdomains,
        "ip_ranges": [str(n) for n in grant.ip_ranges],
    }


def grant_from_dict(data: dict[str, Any]) -> AuthorizationGrant:
    return AuthorizationGrant(
        id=uuid.UUID(data["id"]),
        valid_from=datetime.fromisoformat(data["valid_from"]),
        valid_until=datetime.fromisoformat(data["valid_until"]),
        revoked=bool(data["revoked"]),
        allow_active=bool(data["allow_active"]),
        allow_intrusive=bool(data["allow_intrusive"]),
        include_subdomains=bool(data["include_subdomains"]),
        ip_ranges=tuple(ipaddress.ip_network(n) for n in data["ip_ranges"]),
    )


def asset_to_dict(asset: ScopeAsset) -> dict[str, Any]:
    return {
        "id": str(asset.id),
        "type": asset.type.value,
        "value": asset.value,
        "active": asset.active,
        "authorizations": [grant_to_dict(g) for g in asset.authorizations],
    }


def asset_from_dict(data: dict[str, Any]) -> ScopeAsset:
    return ScopeAsset(
        id=uuid.UUID(data["id"]),
        type=AssetType(data["type"]),
        value=str(data["value"]),
        active=bool(data["active"]),
        authorizations=tuple(grant_from_dict(g) for g in data["authorizations"]),
    )


def decision_to_dict(decision: ScopeDecision) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "target": decision.target,
        "technique": decision.technique.value,
        "asset_id": str(decision.asset_id) if decision.asset_id else None,
        "authorization_id": str(decision.authorization_id) if decision.authorization_id else None,
        "addresses": [
            {"address": v.address, "allowed": v.allowed, "reason": v.reason}
            for v in decision.addresses
        ],
        "reasons": [{"code": r.code, "message": r.message} for r in decision.reasons],
    }


def decision_from_dict(data: dict[str, Any]) -> ScopeDecision:
    return ScopeDecision(
        allowed=bool(data["allowed"]),
        target=str(data["target"]),
        technique=Technique(data["technique"]),
        asset_id=uuid.UUID(data["asset_id"]) if data.get("asset_id") else None,
        authorization_id=(
            uuid.UUID(data["authorization_id"]) if data.get("authorization_id") else None
        ),
        addresses=tuple(
            AddressVerdict(a["address"], bool(a["allowed"]), a.get("reason"))
            for a in data["addresses"]
        ),
        reasons=tuple(Reason(r["code"], r["message"]) for r in data["reasons"]),
    )
