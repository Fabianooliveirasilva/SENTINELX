"""Scope engine decisions."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from sentinelx_security.scope import (
    AssetType,
    AuthorizationGrant,
    NetworkPolicy,
    ScopeAsset,
    ScopeDecision,
    ScopeEngine,
    StaticResolver,
    TargetError,
    Technique,
    normalize_asset_value,
    parse_lab_networks,
)
from sentinelx_security.scope.resolver import ResolutionError

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)

DNS = StaticResolver(
    {
        "example.com": ["93.184.215.14"],
        "www.example.com": ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
        "cdn.example.com": ["151.101.1.1"],  # shared CDN address, not ours
        "rebind.example.com": ["93.184.215.14", "127.0.0.1"],
        "internal.example.com": ["10.0.0.7"],
        "many.example.com": [f"93.184.215.{i}" for i in range(1, 21)],
        "lab.sentinelx.test": ["10.20.0.5"],
    }
)


def grant(**overrides: object) -> AuthorizationGrant:
    values: dict[str, object] = {
        "id": uuid.uuid4(),
        "valid_from": NOW - timedelta(days=1),
        "valid_until": NOW + timedelta(days=30),
        "allow_active": True,
        "ip_ranges": (ipaddress.ip_network("93.184.215.0/24"),),
    }
    values.update(overrides)
    return AuthorizationGrant(**values)  # type: ignore[arg-type]


def asset(
    asset_type: AssetType, value: str, *grants: AuthorizationGrant, active: bool = True
) -> ScopeAsset:
    return ScopeAsset(
        id=uuid.uuid4(),
        type=asset_type,
        value=normalize_asset_value(asset_type, value),
        active=active,
        authorizations=grants,
    )


def engine(**kwargs: object) -> ScopeEngine:
    return ScopeEngine(NetworkPolicy(), DNS, **kwargs)  # type: ignore[arg-type]


async def decide(
    target: str, technique: Technique, *assets: ScopeAsset, eng: ScopeEngine | None = None
) -> ScopeDecision:
    return await (eng or engine()).evaluate(target, technique, list(assets), NOW)


# ----------------------------------------------------------------------------- happy paths


async def test_active_scan_allowed_when_every_address_is_authorized() -> None:
    domain = asset(AssetType.DOMAIN, "example.com", grant())

    decision = await decide("example.com", Technique.ACTIVE, domain)

    assert decision.allowed
    assert decision.asset_id == domain.id
    assert [v.address for v in decision.addresses] == ["93.184.215.14"]
    assert decision.reasons[0].code == "in_scope"


async def test_passive_needs_authorization_but_not_resolution() -> None:
    domain = asset(AssetType.DOMAIN, "cdn.example.com", grant(allow_active=False, ip_ranges=()))

    decision = await decide("cdn.example.com", Technique.PASSIVE, domain)

    assert decision.allowed
    assert decision.addresses == ()
    assert decision.reasons[0].code == "passive_only"


async def test_registered_ip_asset_authorizes_resolved_address() -> None:
    domain = asset(AssetType.DOMAIN, "cdn.example.com", grant(ip_ranges=()))
    ip_asset = asset(AssetType.IP_ADDRESS, "151.101.1.1", grant(ip_ranges=()))

    assert (await decide("cdn.example.com", Technique.ACTIVE, domain, ip_asset)).allowed


async def test_subdomains_require_explicit_opt_in() -> None:
    exact_only = asset(AssetType.DOMAIN, "example.com", grant())
    with_subdomains = asset(AssetType.DOMAIN, "example.com", grant(include_subdomains=True))

    denied = await decide("www.example.com", Technique.ACTIVE, exact_only)
    partially = await decide("www.example.com", Technique.ACTIVE, with_subdomains)

    assert denied.reasons[0].code == "no_matching_asset"
    # IPv4 is authorized, IPv6 address is not in the authorized ranges.
    assert not partially.allowed
    assert {(v.address, v.allowed) for v in partially.addresses} == {
        ("93.184.215.14", True),
        ("2606:2800:21f:cb07:6820:80da:af6b:8b2c", False),
    }
    assert partially.reasons[0].code == "address_not_authorized"


async def test_web_application_scope_is_origin_and_path_bound() -> None:
    app = asset(AssetType.WEB_APPLICATION, "https://example.com/app", grant())

    assert (await decide("https://example.com/app/login", Technique.ACTIVE, app)).allowed
    assert (await decide("https://example.com/app", Technique.ACTIVE, app)).allowed
    for target in (
        "https://example.com/application",  # prefix but not a path boundary
        "https://example.com/admin",
        "http://example.com/app",  # different scheme = different origin
        "https://example.com:8443/app",
        "example.com",
    ):
        assert (await decide(target, Technique.ACTIVE, app)).reasons[
            0
        ].code == "no_matching_asset", target


async def test_service_scope_is_host_and_port_bound() -> None:
    service = asset(AssetType.SERVICE, "example.com:8443", grant())

    assert (await decide("example.com:8443", Technique.ACTIVE, service)).allowed
    assert (await decide("https://example.com:8443/", Technique.ACTIVE, service)).allowed
    assert not (await decide("example.com:22", Technique.ACTIVE, service)).allowed


# ----------------------------------------------------------------------------- denials


async def test_domain_registration_does_not_authorize_every_resolved_ip() -> None:
    domain = asset(AssetType.DOMAIN, "cdn.example.com", grant(ip_ranges=()))

    decision = await decide("cdn.example.com", Technique.ACTIVE, domain)

    assert not decision.allowed
    assert decision.addresses[0].reason == "address_not_authorized"


async def test_dns_rebinding_to_internal_address_is_blocked() -> None:
    domain = asset(AssetType.DOMAIN, "rebind.example.com", grant())

    decision = await decide("rebind.example.com", Technique.ACTIVE, domain)

    assert not decision.allowed
    assert {v.address: v.reason for v in decision.addresses if not v.allowed} == {
        "127.0.0.1": "loopback_address"
    }


async def test_ip_ranges_cannot_authorize_internal_addresses() -> None:
    domain = asset(
        AssetType.DOMAIN,
        "internal.example.com",
        grant(ip_ranges=(ipaddress.ip_network("10.0.0.0/8"),)),
    )

    decision = await decide("internal.example.com", Technique.ACTIVE, domain)

    assert decision.addresses[0].reason == "non_public_address"


@pytest.mark.parametrize(
    ("overrides", "technique", "code"),
    [
        ({"allow_active": False}, Technique.ACTIVE, "technique_not_authorized"),
        ({"allow_intrusive": False}, Technique.INTRUSIVE, "technique_not_authorized"),
        ({"revoked": True}, Technique.ACTIVE, "no_active_authorization"),
        ({"valid_until": NOW}, Technique.ACTIVE, "no_active_authorization"),
        ({"valid_from": NOW + timedelta(seconds=1)}, Technique.PASSIVE, "no_active_authorization"),
    ],
)
async def test_authorization_constraints(
    overrides: dict[str, object], technique: Technique, code: str
) -> None:
    domain = asset(AssetType.DOMAIN, "example.com", grant(**overrides))

    decision = await decide("example.com", technique, domain)

    assert not decision.allowed
    assert decision.reasons[0].code == code


async def test_intrusive_requires_both_flags() -> None:
    domain = asset(AssetType.DOMAIN, "example.com", grant(allow_intrusive=True))

    assert (await decide("example.com", Technique.INTRUSIVE, domain)).allowed


async def test_archived_asset_is_out_of_scope() -> None:
    domain = asset(AssetType.DOMAIN, "example.com", grant(), active=False)

    assert (await decide("example.com", Technique.PASSIVE, domain)).reasons[
        0
    ].code == "asset_inactive"


async def test_most_specific_failure_reason_is_reported() -> None:
    no_auth = asset(AssetType.DOMAIN, "example.com")
    passive_only = asset(AssetType.DOMAIN, "example.com", grant(allow_active=False))

    decision = await decide("example.com", Technique.ACTIVE, no_auth, passive_only)

    assert decision.reasons[0].code == "technique_not_authorized"


@pytest.mark.parametrize(
    ("target", "code"),
    [
        ("http://user:pw@example.com/", "credentials_in_url"),
        ("2130706433", "ambiguous_numeric_host"),
        ("printer.local", "special_use_hostname"),
        ("db.internal", "special_use_hostname"),
        ("not a target", "invalid_characters"),
    ],
)
async def test_invalid_and_special_targets_are_denied(target: str, code: str) -> None:
    decision = await decide(
        target, Technique.PASSIVE, asset(AssetType.DOMAIN, "example.com", grant())
    )

    assert not decision.allowed
    assert decision.reasons[0].code == code


async def test_ip_target_is_checked_against_network_policy() -> None:
    lab_ip = asset(AssetType.IP_ADDRESS, "93.184.215.14", grant(ip_ranges=()))

    assert (await decide("93.184.215.14", Technique.ACTIVE, lab_ip)).allowed
    blocked = await decide("127.0.0.1", Technique.ACTIVE, lab_ip)
    assert blocked.reasons[0].code == "loopback_address"


async def test_resolution_failures_and_fanout_limits() -> None:
    missing = asset(AssetType.DOMAIN, "missing.example.com", grant())
    many = asset(AssetType.DOMAIN, "many.example.com", grant())

    assert (await decide("missing.example.com", Technique.ACTIVE, missing)).reasons[
        0
    ].code == "dns_no_records"
    assert (await decide("many.example.com", Technique.ACTIVE, many)).reasons[
        0
    ].code == "too_many_addresses"


async def test_lab_configuration_enables_internal_targets() -> None:
    lab_engine = ScopeEngine(
        NetworkPolicy(parse_lab_networks(["10.20.0.0/16"])),
        DNS,
        lab_domains=["sentinelx.test"],
    )
    lab = asset(
        AssetType.DOMAIN,
        "lab.sentinelx.test",
        grant(ip_ranges=(ipaddress.ip_network("10.20.0.0/16"),)),
    )

    decision = await decide("lab.sentinelx.test", Technique.ACTIVE, lab, eng=lab_engine)

    assert decision.allowed
    assert lab_engine.registration_problem(AssetType.DOMAIN, "lab.sentinelx.test") is None
    assert engine().registration_problem(AssetType.DOMAIN, "lab.sentinelx.test") is not None


# ----------------------------------------------------------------------------- redirects


async def test_redirects_are_validated_per_hop() -> None:
    app = asset(AssetType.WEB_APPLICATION, "https://example.com/", grant())
    eng = engine()

    same_site = await eng.evaluate_redirect(
        "https://example.com/login", "/dashboard", Technique.ACTIVE, [app], NOW
    )
    offsite = await eng.evaluate_redirect(
        "https://example.com/login", "https://evil.example.net/", Technique.ACTIVE, [app], NOW
    )
    to_metadata = await eng.evaluate_redirect(
        "https://example.com/",
        "http://169.254.169.254/latest/meta-data/",
        Technique.ACTIVE,
        [app],
        NOW,
    )

    assert same_site.allowed
    assert same_site.target == "https://example.com/dashboard"
    assert offsite.reasons[0].code == "no_matching_asset"
    assert not to_metadata.allowed


# ----------------------------------------------------------------------------- asset values


@pytest.mark.parametrize(
    ("asset_type", "raw", "normalized"),
    [
        (AssetType.DOMAIN, "Example.COM.", "example.com"),
        (AssetType.SUBDOMAIN, "API.Example.com", "api.example.com"),
        (AssetType.IP_ADDRESS, "2001:0db8:0000::0001", "2001:db8::1"),
        (AssetType.WEB_APPLICATION, "https://Example.com:443/App", "https://example.com/App"),
        (AssetType.API_ENDPOINT, "http://api.example.com/v1/", "http://api.example.com/v1/"),
        (AssetType.SERVICE, "Mail.Example.com:587", "mail.example.com:587"),
    ],
)
def test_asset_values_are_normalized(asset_type: AssetType, raw: str, normalized: str) -> None:
    assert normalize_asset_value(asset_type, raw) == normalized


@pytest.mark.parametrize(
    ("asset_type", "raw", "code"),
    [
        (AssetType.SUBDOMAIN, "example.com", "invalid_subdomain"),
        (AssetType.IP_ADDRESS, "example.com", "invalid_ip"),
        (AssetType.WEB_APPLICATION, "example.com", "url_required"),
        (AssetType.SERVICE, "example.com", "host_port_required"),
        (AssetType.SERVICE, "https://example.com/", "host_port_required"),
    ],
)
def test_asset_values_must_match_their_type(asset_type: AssetType, raw: str, code: str) -> None:
    with pytest.raises(TargetError) as excinfo:
        normalize_asset_value(asset_type, raw)
    assert excinfo.value.code == code


@pytest.mark.parametrize(
    ("asset_type", "value", "code"),
    [
        (AssetType.IP_ADDRESS, "10.0.0.1", "non_public_address"),
        (AssetType.IP_ADDRESS, "169.254.169.254", "metadata_endpoint"),
        (AssetType.DOMAIN, "corp.internal", "special_use_hostname"),
        (AssetType.WEB_APPLICATION, "http://127.0.0.1:8080/", "loopback_address"),
        (AssetType.SERVICE, "router.lan:22", "special_use_hostname"),
    ],
)
def test_internal_targets_cannot_be_registered(
    asset_type: AssetType, value: str, code: str
) -> None:
    problem = engine().registration_problem(asset_type, normalize_asset_value(asset_type, value))

    assert problem is not None
    assert problem.code == code


async def test_static_resolver_raises_for_unknown_hosts() -> None:
    with pytest.raises(ResolutionError):
        await DNS.resolve("unknown.example.com")


@pytest.mark.parametrize(
    ("target", "code"),
    [
        ("http://[::ffff:169.254.169.254]/latest/meta-data/", "embedded_metadata_endpoint"),
        ("169.254.169.254", "metadata_endpoint"),
        ("10.0.0.1:22", "non_public_address"),
        ("[::1]:8080", "loopback_address"),
    ],
)
async def test_blocked_literal_ips_report_the_policy_reason_even_for_passive(
    target: str, code: str
) -> None:
    decision = await decide(target, Technique.PASSIVE)

    assert not decision.allowed
    assert decision.reasons[0].code == code
    assert decision.addresses[0].allowed is False
