"""Scanner adapters and the scan executor."""

from __future__ import annotations

from dataclasses import dataclass

from sentinelx_security.scanners.base import (
    Evidence,
    Observation,
    RawOutput,
    ScanContext,
    ScanError,
    Scanner,
    ScannerName,
    UnsupportedTargetError,
)
from sentinelx_security.scanners.dns import DnspythonQuery, DnsScanner
from sentinelx_security.scanners.executor import ScanOutcome, ScanRequest, execute_scan
from sentinelx_security.scanners.http import HttpScanner
from sentinelx_security.scanners.nmap import NmapScanner
from sentinelx_security.scanners.subdomains import DEFAULT_CRTSH_URL, SubdomainScanner
from sentinelx_security.scanners.tls import TlsScanner


@dataclass(frozen=True, slots=True)
class ScannerConfig:
    nmap_binary: str = "nmap"
    nmap_datadir: str | None = None
    dns_timeout_seconds: float = 5.0
    dns_nameservers: tuple[str, ...] = ()
    crtsh_url: str = DEFAULT_CRTSH_URL
    passive_sources_enabled: bool = True


def build_scanners(config: ScannerConfig) -> dict[ScannerName, Scanner]:
    return {
        ScannerName.DNS: DnsScanner(
            DnspythonQuery(
                timeout_seconds=config.dns_timeout_seconds, nameservers=config.dns_nameservers
            )
        ),
        ScannerName.SUBDOMAINS: SubdomainScanner(
            base_url=config.crtsh_url, enabled=config.passive_sources_enabled
        ),
        ScannerName.TLS: TlsScanner(),
        ScannerName.NMAP: NmapScanner(binary=config.nmap_binary, datadir=config.nmap_datadir),
        ScannerName.HTTP: HttpScanner(),
    }


# Catalog used by the API (no worker-side configuration needed).
CATALOG: dict[ScannerName, type[Scanner]] = {
    ScannerName.DNS: DnsScanner,
    ScannerName.SUBDOMAINS: SubdomainScanner,
    ScannerName.TLS: TlsScanner,
    ScannerName.NMAP: NmapScanner,
    ScannerName.HTTP: HttpScanner,
}

__all__ = [
    "CATALOG",
    "Evidence",
    "Observation",
    "RawOutput",
    "ScanContext",
    "ScanError",
    "ScanOutcome",
    "ScanRequest",
    "Scanner",
    "ScannerConfig",
    "ScannerName",
    "UnsupportedTargetError",
    "build_scanners",
    "execute_scan",
]
