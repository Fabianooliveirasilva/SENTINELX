"""Scope enforcement: what may be tested, how, and at which addresses."""

from sentinelx_security.scope.engine import (
    AssetType,
    AuthorizationGrant,
    Reason,
    ScopeAsset,
    ScopeDecision,
    ScopeEngine,
    Technique,
    normalize_asset_value,
)
from sentinelx_security.scope.network_policy import (
    AddressVerdict,
    NetworkPolicy,
    parse_lab_networks,
)
from sentinelx_security.scope.resolver import DnsResolver, ResolutionError, Resolver, StaticResolver
from sentinelx_security.scope.targets import Target, TargetError, parse_target

__all__ = [
    "AddressVerdict",
    "AssetType",
    "AuthorizationGrant",
    "DnsResolver",
    "NetworkPolicy",
    "Reason",
    "ResolutionError",
    "Resolver",
    "ScopeAsset",
    "ScopeDecision",
    "ScopeEngine",
    "StaticResolver",
    "Target",
    "TargetError",
    "Technique",
    "normalize_asset_value",
    "parse_lab_networks",
    "parse_target",
]
