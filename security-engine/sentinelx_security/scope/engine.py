"""Scope engine: decides whether a target may be tested with a given technique.

Decision procedure (deny by default; every denial carries a reason code):

1. Parse and normalize the target (``targets.parse_target``).
2. Reject special-use hostnames unless they belong to a configured lab domain.
3. Find a registered, active asset that covers the target, together with an
   authorization that is currently valid and permits the technique.
4. Passive techniques stop here: they never contact the target.
5. Active techniques resolve the host once (the pinned address set) and require
   **every** address to (a) pass the network policy and (b) be explicitly
   authorized — inside an authorization's IP ranges or registered as an
   authorized IP asset. Registering a domain never implies permission to test
   every address it resolves to (shared hosting, CDNs, third parties).
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Final
from urllib.parse import urljoin

from sentinelx_security.scope.network_policy import AddressVerdict, IPNetwork, NetworkPolicy
from sentinelx_security.scope.resolver import ResolutionError, Resolver
from sentinelx_security.scope.targets import (
    IPAddress,
    Target,
    TargetError,
    is_special_use_hostname,
    is_subdomain_of,
    normalize_hostname,
    parse_ip,
    parse_target,
)

MAX_RESOLVED_ADDRESSES: Final = 16


class Technique(StrEnum):
    PASSIVE = "passive"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"


class AssetType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    WEB_APPLICATION = "web_application"
    API_ENDPOINT = "api_endpoint"
    SERVICE = "service"


HOST_TYPES: Final = frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN})
URL_TYPES: Final = frozenset({AssetType.WEB_APPLICATION, AssetType.API_ENDPOINT})


@dataclass(frozen=True, slots=True)
class Reason:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class AuthorizationGrant:
    id: uuid.UUID
    valid_from: datetime
    valid_until: datetime
    revoked: bool = False
    allow_active: bool = False
    allow_intrusive: bool = False
    include_subdomains: bool = False
    ip_ranges: tuple[IPNetwork, ...] = ()

    def is_current(self, now: datetime) -> bool:
        return not self.revoked and self.valid_from <= now < self.valid_until

    def permits(self, technique: Technique) -> bool:
        if technique is Technique.PASSIVE:
            return True
        if technique is Technique.ACTIVE:
            return self.allow_active
        return self.allow_active and self.allow_intrusive

    def covers_address(self, ip: IPAddress) -> bool:
        return any(ip.version == net.version and ip in net for net in self.ip_ranges)


@dataclass(frozen=True, slots=True)
class ScopeAsset:
    id: uuid.UUID
    type: AssetType
    value: str
    active: bool = True
    authorizations: tuple[AuthorizationGrant, ...] = ()


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    allowed: bool
    target: str
    technique: Technique
    asset_id: uuid.UUID | None = None
    authorization_id: uuid.UUID | None = None
    addresses: tuple[AddressVerdict, ...] = ()
    reasons: tuple[Reason, ...] = field(default_factory=tuple)


# ----------------------------------------------------------------------------- asset values


def normalize_asset_value(asset_type: AssetType, raw: str) -> str:
    """Canonical stored form of an asset value (raises TargetError when invalid)."""
    if asset_type in HOST_TYPES:
        host = normalize_hostname(raw)
        if asset_type is AssetType.SUBDOMAIN and host.count(".") < 2:
            raise TargetError("invalid_subdomain", "A subdomain needs at least three labels.")
        return host
    if asset_type is AssetType.IP_ADDRESS:
        return parse_ip(raw).compressed
    target = parse_target(raw)
    if asset_type in URL_TYPES:
        if not target.is_url:
            raise TargetError("url_required", "Web applications and APIs need an http(s) URL.")
        return str(target)
    if target.is_url or target.port is None:
        raise TargetError("host_port_required", "Services are registered as host:port.")
    return str(target)


def asset_host(asset: ScopeAsset) -> str:
    if asset.type in HOST_TYPES or asset.type is AssetType.IP_ADDRESS:
        return asset.value
    return parse_target(asset.value).host


def _path_within(path: str, prefix: str) -> bool:
    if prefix in ("", "/"):
        return True
    base = prefix.rstrip("/")
    return path == base or path.startswith(f"{base}/")


def asset_covers(asset: ScopeAsset, target: Target, *, include_subdomains: bool) -> bool:
    if asset.type in HOST_TYPES:
        return target.host == asset.value or (
            include_subdomains and not target.is_ip and is_subdomain_of(target.host, asset.value)
        )
    if asset.type is AssetType.IP_ADDRESS:
        return target.ip is not None and target.ip == ipaddress.ip_address(asset.value)
    registered = parse_target(asset.value)
    if asset.type in URL_TYPES:
        return (
            target.is_url
            and target.origin == registered.origin
            and _path_within(target.path or "/", registered.path or "/")
        )
    return target.host == registered.host and target.effective_port == registered.port


# ----------------------------------------------------------------------------- engine


class ScopeEngine:
    def __init__(
        self,
        policy: NetworkPolicy,
        resolver: Resolver,
        *,
        lab_domains: Sequence[str] = (),
        max_addresses: int = MAX_RESOLVED_ADDRESSES,
    ) -> None:
        self._policy = policy
        self._resolver = resolver
        self._lab_domains = tuple(normalize_hostname(d) for d in lab_domains)
        self._max_addresses = max_addresses

    @property
    def policy(self) -> NetworkPolicy:
        return self._policy

    def is_lab_hostname(self, host: str) -> bool:
        return any(host == d or is_subdomain_of(host, d) for d in self._lab_domains)

    def registration_problem(self, asset_type: AssetType, value: str) -> Reason | None:
        """Reasons an (already normalized) value may not be registered as an asset."""
        host = value if asset_type in HOST_TYPES else None
        if asset_type is AssetType.IP_ADDRESS:
            verdict = self._policy.check(ipaddress.ip_address(value))
            if not verdict.allowed:
                return Reason(
                    verdict.reason or "address_blocked",
                    "This address is not publicly routable or is always blocked.",
                )
            return None
        if host is None:
            target = parse_target(value)
            if target.ip is not None:
                verdict = self._policy.check(target.ip)
                if not verdict.allowed:
                    return Reason(
                        verdict.reason or "address_blocked",
                        "This address is not publicly routable or is always blocked.",
                    )
                return None
            host = target.host
        if is_special_use_hostname(host) and not self.is_lab_hostname(host):
            return Reason(
                "special_use_hostname",
                "Special-use and internal names are not allowed outside configured labs.",
            )
        return None

    @staticmethod
    def _deny(
        target: str,
        technique: Technique,
        code: str,
        message: str,
        *,
        selection: tuple[ScopeAsset, AuthorizationGrant] | None = None,
    ) -> ScopeDecision:
        return ScopeDecision(
            allowed=False,
            target=target,
            technique=technique,
            asset_id=selection[0].id if selection else None,
            authorization_id=selection[1].id if selection else None,
            reasons=(Reason(code, message),),
        )

    def _select(
        self, target: Target, technique: Technique, assets: Iterable[ScopeAsset], now: datetime
    ) -> tuple[ScopeAsset, AuthorizationGrant] | Reason:
        """Pick the covering asset/authorization, or explain why none applies."""
        best_reason = Reason(
            "no_matching_asset", "No registered asset in this project covers the target."
        )
        rank = {
            "no_matching_asset": 0,
            "asset_inactive": 1,
            "no_active_authorization": 2,
            "technique_not_authorized": 3,
        }
        for asset in assets:
            exact = asset_covers(asset, target, include_subdomains=False)
            via_subdomains = [
                g
                for g in asset.authorizations
                if g.include_subdomains and asset_covers(asset, target, include_subdomains=True)
            ]
            if not exact and not via_subdomains:
                continue
            if not asset.active:
                candidate = Reason("asset_inactive", "The matching asset is archived.")
            else:
                grants = [
                    g
                    for g in (asset.authorizations if exact else via_subdomains)
                    if g.is_current(now)
                ]
                permitted = [g for g in grants if g.permits(technique)]
                if permitted:
                    return asset, permitted[0]
                candidate = (
                    Reason(
                        "technique_not_authorized",
                        f"The authorization does not permit {technique.value} testing.",
                    )
                    if grants
                    else Reason(
                        "no_active_authorization",
                        "The asset has no authorization valid at this time.",
                    )
                )
            if rank[candidate.code] > rank[best_reason.code]:
                best_reason = candidate
        return best_reason

    def _authorized_ips(
        self, assets: Iterable[ScopeAsset], technique: Technique, now: datetime
    ) -> set[IPAddress]:
        return {
            ipaddress.ip_address(asset.value)
            for asset in assets
            if asset.type is AssetType.IP_ADDRESS
            and asset.active
            and any(g.is_current(now) and g.permits(technique) for g in asset.authorizations)
        }

    async def evaluate(
        self, raw_target: str, technique: Technique, assets: Sequence[ScopeAsset], now: datetime
    ) -> ScopeDecision:
        try:
            target = parse_target(raw_target)
        except TargetError as exc:
            return self._deny(raw_target.strip()[:256], technique, exc.code, exc.message)
        shown = str(target)

        if (
            not target.is_ip
            and is_special_use_hostname(target.host)
            and not self.is_lab_hostname(target.host)
        ):
            return self._deny(
                shown,
                technique,
                "special_use_hostname",
                "Special-use and internal names are never in scope.",
            )

        # Literal IPs that the network policy refuses are denied up front, with the
        # precise reason (e.g. a metadata endpoint hidden in IPv4-mapped IPv6).
        if target.ip is not None:
            verdict = self._policy.check(target.ip)
            if not verdict.allowed:
                return ScopeDecision(
                    allowed=False,
                    target=shown,
                    technique=technique,
                    addresses=(verdict,),
                    reasons=(
                        Reason(
                            verdict.reason or "address_blocked",
                            f"{verdict.address} is never a permitted target ({verdict.reason}).",
                        ),
                    ),
                )

        selection = self._select(target, technique, assets, now)
        if isinstance(selection, Reason):
            return self._deny(shown, technique, selection.code, selection.message)
        asset, grant = selection

        if technique is Technique.PASSIVE:
            return ScopeDecision(
                allowed=True,
                target=shown,
                technique=technique,
                asset_id=asset.id,
                authorization_id=grant.id,
                reasons=(Reason("passive_only", "Passive techniques do not contact the target."),),
            )

        if target.ip is not None:
            addresses: list[IPAddress] = [target.ip]
        else:
            try:
                addresses = await self._resolver.resolve(target.host)
            except ResolutionError as exc:
                return self._deny(shown, technique, exc.code, str(exc), selection=selection)
            if len(addresses) > self._max_addresses:
                return self._deny(
                    shown,
                    technique,
                    "too_many_addresses",
                    "The hostname resolves to too many addresses.",
                    selection=selection,
                )

        authorized_ips = self._authorized_ips(assets, technique, now)
        verdicts: list[AddressVerdict] = []
        for ip in addresses:
            verdict = self._policy.check(ip)
            if verdict.allowed and not (grant.covers_address(ip) or ip in authorized_ips):
                verdict = AddressVerdict(
                    ip.compressed, allowed=False, reason="address_not_authorized"
                )
            verdicts.append(verdict)

        allowed = all(v.allowed for v in verdicts)
        reasons = (
            (Reason("in_scope", "Every resolved address is permitted and explicitly authorized."),)
            if allowed
            else tuple(
                Reason(v.reason or "address_blocked", f"{v.address} is not permitted ({v.reason}).")
                for v in verdicts
                if not v.allowed
            )
        )
        return ScopeDecision(
            allowed=allowed,
            target=shown,
            technique=technique,
            asset_id=asset.id,
            authorization_id=grant.id,
            addresses=tuple(verdicts),
            reasons=reasons,
        )

    async def evaluate_redirect(
        self,
        current_url: str,
        location: str,
        technique: Technique,
        assets: Sequence[ScopeAsset],
        now: datetime,
    ) -> ScopeDecision:
        """Validate an HTTP redirect hop: the destination must be in scope on its own."""
        return await self.evaluate(urljoin(current_url, location), technique, assets, now)
