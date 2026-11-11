"""Deny-by-default network policy for addresses SentinelX may contact.

An address is permitted only when it is globally routable (``is_global``) or
inside an administrator-configured lab network. Several classes are refused
unconditionally, even inside lab networks: loopback, unspecified, link-local
(which includes cloud metadata services), multicast and reserved space.

IPv6 forms that embed an IPv4 address (IPv4-mapped, IPv4-compatible, NAT64,
6to4, Teredo) are unwrapped and the embedded address must pass as well; this
closes bypasses such as ``::ffff:127.0.0.1`` or ``64:ff9b::a9fe:a9fe``.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

from sentinelx_security.scope.targets import IPAddress

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Explicit metadata endpoints. Most are link-local already; listing them keeps the
# intent auditable and covers providers that use other ranges.
METADATA_ADDRESSES: Final = frozenset(
    ipaddress.ip_address(a)
    for a in (
        "169.254.169.254",  # AWS, GCP, Azure, OpenStack, DigitalOcean
        "169.254.170.2",  # AWS ECS task metadata
        "100.100.100.200",  # Alibaba Cloud
        "fd00:ec2::254",  # AWS IPv6 IMDS
    )
)

# Ranges a lab network may never overlap (the same classes _hard_block_reason refuses).
ALWAYS_BLOCKED_NETWORKS: Final[tuple[IPNetwork, ...]] = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
        *(f"{a}/{a.max_prefixlen}" for a in METADATA_ADDRESSES),
    )
)

_NAT64_PREFIXES: Final = (
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("64:ff9b:1::/48"),
)
_IPV4_COMPATIBLE: Final = ipaddress.IPv6Network("::/96")


@dataclass(frozen=True, slots=True)
class AddressVerdict:
    address: str
    allowed: bool
    reason: str | None = None


def embedded_ipv4(ip: IPAddress) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses embedded in an IPv6 address by common transition mechanisms."""
    if not isinstance(ip, ipaddress.IPv6Address):
        return []
    found: list[ipaddress.IPv4Address] = []
    if ip.ipv4_mapped is not None:
        found.append(ip.ipv4_mapped)
    if ip.sixtofour is not None:
        found.append(ip.sixtofour)
    if ip.teredo is not None:
        found.extend(ip.teredo)
    low32 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if any(ip in prefix for prefix in _NAT64_PREFIXES) or (ip in _IPV4_COMPATIBLE and int(ip) > 1):
        found.append(low32)
    return found


def _hard_block_reason(ip: IPAddress) -> str | None:
    if ip in METADATA_ADDRESSES:
        return "metadata_endpoint"
    if ip.is_unspecified:
        return "unspecified_address"
    if ip.is_loopback:
        return "loopback_address"
    if ip.is_link_local:
        return "link_local_address"
    if ip.is_multicast:
        return "multicast_address"
    if isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local:
        return "site_local_address"
    if ip.is_reserved:
        return "reserved_address"
    return None


def parse_lab_networks(values: Iterable[str]) -> tuple[IPNetwork, ...]:
    """Validate administrator-supplied lab networks.

    Lab networks may contain private space, but never ranges that are blocked
    unconditionally (loopback, link-local, multicast, unspecified, reserved).
    """
    networks: list[IPNetwork] = []
    for value in values:
        network = ipaddress.ip_network(value.strip(), strict=True)
        if any(
            network.version == blocked.version and network.overlaps(blocked)
            for blocked in ALWAYS_BLOCKED_NETWORKS
        ):
            raise ValueError(f"lab network {value!r} overlaps an always-blocked range")
        networks.append(network)
    return tuple(networks)


class NetworkPolicy:
    def __init__(self, lab_networks: Sequence[IPNetwork] = ()) -> None:
        self._lab_networks = tuple(lab_networks)

    @property
    def lab_networks(self) -> tuple[IPNetwork, ...]:
        return self._lab_networks

    def in_lab(self, ip: IPAddress) -> bool:
        return any(ip.version == net.version and ip in net for net in self._lab_networks)

    def check(self, ip: IPAddress) -> AddressVerdict:
        address = ip.compressed
        # Embedded IPv4 destinations are judged first and on their own: they are the
        # real destination, and the stdlib's classification of the outer IPv6 form
        # has changed between Python patch releases (CVE-2024-4032 fixes).
        for embedded in embedded_ipv4(ip):
            reason = _hard_block_reason(embedded)
            if reason is None and not self.in_lab(embedded) and not embedded.is_global:
                reason = "non_public_address"
            if reason is not None:
                return AddressVerdict(address, allowed=False, reason=f"embedded_{reason}")
        reason = _hard_block_reason(ip)
        if reason is None and not self.in_lab(ip) and not ip.is_global:
            reason = "non_public_address"
        if reason is not None:
            return AddressVerdict(address, allowed=False, reason=reason)
        return AddressVerdict(address, allowed=True)
