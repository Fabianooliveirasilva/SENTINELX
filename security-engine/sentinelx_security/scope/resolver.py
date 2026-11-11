"""Hostname resolution for scope decisions.

Resolution happens once per decision; the resulting addresses are returned to
the caller as the *pinned* set. Scanners (Phase 4) must connect to these exact
addresses and re-validate them at execution time, which defeats DNS rebinding
(a name that resolves to a public address during validation and to an internal
one when the scanner connects).
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Mapping, Sequence
from typing import Protocol

import dns.asyncresolver
import dns.exception
import dns.resolver

from sentinelx_security.scope.targets import IPAddress


class ResolutionError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class Resolver(Protocol):
    async def resolve(self, hostname: str) -> list[IPAddress]:
        """Return all A/AAAA addresses, or raise ResolutionError."""


class DnsResolver:
    def __init__(self, *, timeout_seconds: float = 3.0, nameservers: Sequence[str] = ()) -> None:
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.lifetime = timeout_seconds
        self._resolver.timeout = timeout_seconds
        if nameservers:
            self._resolver.nameservers = list(nameservers)

    async def _query(self, hostname: str, rdtype: str) -> list[IPAddress]:
        try:
            answer = await self._resolver.resolve(hostname, rdtype, search=False)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        return [ipaddress.ip_address(record.to_text()) for record in answer]

    async def resolve(self, hostname: str) -> list[IPAddress]:
        try:
            v4, v6 = await asyncio.gather(self._query(hostname, "A"), self._query(hostname, "AAAA"))
        except dns.exception.Timeout as exc:
            raise ResolutionError("dns_timeout", "DNS resolution timed out.") from exc
        except dns.exception.DNSException as exc:
            raise ResolutionError("dns_error", "DNS resolution failed.") from exc
        addresses = sorted({*v4, *v6}, key=lambda ip: (ip.version, int(ip)))
        if not addresses:
            raise ResolutionError("dns_no_records", "The hostname has no A or AAAA records.")
        return addresses


class StaticResolver:
    """Deterministic resolver for tests and offline demos."""

    def __init__(self, records: Mapping[str, Sequence[str]]) -> None:
        self._records = {
            host: [ipaddress.ip_address(a) for a in addresses]
            for host, addresses in records.items()
        }

    async def resolve(self, hostname: str) -> list[IPAddress]:
        addresses = self._records.get(hostname)
        if not addresses:
            raise ResolutionError("dns_no_records", "The hostname has no A or AAAA records.")
        return list(addresses)
