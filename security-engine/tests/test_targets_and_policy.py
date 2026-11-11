"""Target parsing and network policy, including known SSRF/scope bypass forms."""

from __future__ import annotations

import ipaddress

import pytest

from sentinelx_security.scope import NetworkPolicy, TargetError, parse_lab_networks, parse_target
from sentinelx_security.scope.network_policy import embedded_ipv4
from sentinelx_security.scope.targets import normalize_hostname

# ----------------------------------------------------------------------------- parsing


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("  api.example.com  ", "api.example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("93.184.215.14", "93.184.215.14"),
        ("2606:2800:21f:cb07:6820:80da:af6b:8b2c", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("example.com:8443", "example.com:8443"),
        ("[2001:db8::1]:443", "[2001:db8::1]:443"),
        ("HTTPS://Example.com:443/Login", "https://example.com/Login"),
        ("http://example.com", "http://example.com/"),
        ("https://example.com:8443/api/v1?x=1#frag", "https://example.com:8443/api/v1"),
        ("http://[2001:db8::1]:8080/", "http://[2001:db8::1]:8080/"),
    ],
)
def test_targets_are_normalized(raw: str, expected: str) -> None:
    assert str(parse_target(raw)) == expected


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("", "empty_target"),
        ("exa mple.com", "invalid_characters"),
        ("example.com\n", "empty_target"),  # stripped, then still valid? (see next case)
        ("ex\x00ample.com", "invalid_characters"),
        ("localhost", "invalid_hostname"),  # single label
        ("*.example.com", "invalid_hostname"),
        ("-bad.example.com", "invalid_hostname"),
        ("a" * 64 + ".com", "invalid_hostname"),
        ("ftp://example.com", "unsupported_scheme"),
        ("file:///etc/passwd", "unsupported_scheme"),
        ("javascript://example.com", "unsupported_scheme"),
        ("http://user:pass@example.com/", "credentials_in_url"),
        ("http://example.com@evil.example/", "credentials_in_url"),
        ("http://:80/", "invalid_url"),
        ("http://example.com:99999/", "invalid_url"),
        ("example.com:0", "invalid_port"),
        ("example.com/path", "invalid_target"),
        ("fe80::1%eth0", "invalid_target"),
        ("[fe80::1%25eth0]:80", "invalid_ip"),
        # Numeric forms that libc resolvers would turn into an IP (127.0.0.1):
        ("2130706433", "ambiguous_numeric_host"),
        ("0x7f000001", "ambiguous_numeric_host"),
        ("0177.0.0.1", "ambiguous_numeric_host"),
        ("127.1", "ambiguous_numeric_host"),
        ("0x7f.0x0.0x0.0x1", "ambiguous_numeric_host"),
        ("example.123", "ambiguous_numeric_host"),
        ("http://2130706433/", "ambiguous_numeric_host"),
        ("http://0x7f.1/", "ambiguous_numeric_host"),
        ("x" * 3000, "target_too_long"),
    ],
)
def test_invalid_or_ambiguous_targets_are_rejected(raw: str, code: str) -> None:
    if raw == "example.com\n":
        assert str(parse_target(raw)) == "example.com"  # surrounding whitespace is trimmed
        return
    with pytest.raises(TargetError) as excinfo:
        parse_target(raw)
    assert excinfo.value.code == code


def test_homoglyph_hostname_never_equals_ascii_name() -> None:
    # Cyrillic small letter a (U+0430) instead of the Latin letter: a homoglyph.
    assert normalize_hostname("exаmple.com") != normalize_hostname("example.com")  # noqa: RUF001 - deliberate homoglyph


def test_target_properties() -> None:
    url = parse_target("https://example.com/app")
    assert url.is_url
    assert url.effective_port == 443
    assert url.origin == "https://example.com"
    service = parse_target("10.0.0.1:22")
    assert service.is_ip
    assert service.effective_port == 22
    with pytest.raises(ValueError, match="no scheme"):
        _ = service.origin


# ----------------------------------------------------------------------------- network policy

POLICY = NetworkPolicy()


@pytest.mark.parametrize(
    ("address", "reason"),
    [
        ("127.0.0.1", "loopback_address"),
        ("127.255.255.254", "loopback_address"),
        ("::1", "loopback_address"),
        ("0.0.0.0", "unspecified_address"),
        ("::", "unspecified_address"),
        ("169.254.169.254", "metadata_endpoint"),
        ("169.254.170.2", "metadata_endpoint"),
        ("fd00:ec2::254", "metadata_endpoint"),
        ("100.100.100.200", "metadata_endpoint"),
        ("169.254.1.1", "link_local_address"),
        ("fe80::1", "link_local_address"),
        ("224.0.0.1", "multicast_address"),
        ("ff02::1", "multicast_address"),
        ("fec0::1", "site_local_address"),
        ("240.0.0.1", "reserved_address"),
        ("10.0.0.5", "non_public_address"),
        ("172.16.3.4", "non_public_address"),
        ("192.168.1.1", "non_public_address"),
        ("100.64.0.1", "non_public_address"),
        ("198.18.0.1", "non_public_address"),
        ("192.0.2.10", "non_public_address"),
        ("fc00::1", "non_public_address"),
        ("2001:db8::1", "non_public_address"),
        # IPv4 embedded in IPv6 — classic filter bypasses:
        ("::ffff:127.0.0.1", "embedded_loopback_address"),
        ("::ffff:169.254.169.254", "embedded_metadata_endpoint"),
        ("::ffff:10.0.0.1", "embedded_non_public_address"),
        ("::127.0.0.1", "embedded_loopback_address"),
        ("64:ff9b::a9fe:a9fe", "embedded_metadata_endpoint"),
        ("64:ff9b::7f00:1", "embedded_loopback_address"),
        ("2002:7f00:0001::1", "embedded_loopback_address"),
        ("2002:0a00:0001::1", "embedded_non_public_address"),
    ],
)
def test_blocked_addresses(address: str, reason: str) -> None:
    verdict = POLICY.check(ipaddress.ip_address(address))

    assert verdict.allowed is False
    assert verdict.reason == reason


@pytest.mark.parametrize("address", ["93.184.215.14", "8.8.8.8", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(address: str) -> None:
    assert POLICY.check(ipaddress.ip_address(address)).allowed


def test_teredo_embedded_client_is_checked() -> None:
    teredo = ipaddress.IPv6Address("2001:0:4136:e378:8000:63bf:3fff:fdd2")
    assert {str(a) for a in embedded_ipv4(teredo)} == {"65.54.227.120", "192.0.2.45"}
    assert not POLICY.check(teredo).allowed


def test_lab_networks_allow_private_space_only() -> None:
    lab = NetworkPolicy(parse_lab_networks(["10.10.0.0/16", "fd12:3456::/64"]))

    assert lab.check(ipaddress.ip_address("10.10.4.2")).allowed
    assert lab.check(ipaddress.ip_address("fd12:3456::5")).allowed
    assert not lab.check(ipaddress.ip_address("10.11.0.1")).allowed
    # Hard blocks still apply inside a lab.
    assert not lab.check(ipaddress.ip_address("127.0.0.1")).allowed


@pytest.mark.parametrize(
    "network",
    [
        "127.0.0.0/8",
        "0.0.0.0/0",
        "169.254.0.0/16",
        "160.0.0.0/3",
        "224.0.0.0/8",
        "fe80::/64",
        "::/0",
    ],
)
def test_lab_networks_cannot_overlap_hard_blocked_ranges(network: str) -> None:
    with pytest.raises(ValueError, match="always-blocked"):
        parse_lab_networks([network])


def test_lab_network_must_be_a_network_address() -> None:
    with pytest.raises(ValueError, match="host bits"):
        parse_lab_networks(["10.0.0.1/24"])
