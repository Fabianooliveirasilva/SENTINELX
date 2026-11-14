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
from sentinelx_security.scanners.nuclei import NucleiScanner
from sentinelx_security.scanners.subdomains import DEFAULT_CRTSH_URL, SubdomainScanner
from sentinelx_security.scanners.tls import TlsScanner
from sentinelx_security.scanners.zap import ZapScanner


@dataclass(frozen=True, slots=True)
class ScannerConfig:
    nmap_binary: str = "nmap"
    nmap_datadir: str | None = None
    dns_timeout_seconds: float = 5.0
    dns_nameservers: tuple[str, ...] = ()
    crtsh_url: str = DEFAULT_CRTSH_URL
    passive_sources_enabled: bool = True
    nuclei_binary: str = "nuclei"
    nuclei_templates_dir: str = "/opt/nuclei-templates"
    nuclei_version: str = "unknown"
    nuclei_templates_version: str = "unknown"
    zap_api_url: str = "http://zap:8080"
    zap_api_key: str = ""
    zap_proxy_bind: str = "0.0.0.0"  # noqa: S104  # nosec B104 - internal ZAP network
    zap_proxy_port: int = 8899
    zap_proxy_host: str = "scanner-zap"


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
        ScannerName.NUCLEI: NucleiScanner(
            binary=config.nuclei_binary,
            templates_dir=config.nuclei_templates_dir,
            version=config.nuclei_version,
            templates_version=config.nuclei_templates_version,
        ),
        ScannerName.ZAP: ZapScanner(
            api_url=config.zap_api_url,
            api_key=config.zap_api_key,
            proxy_bind=config.zap_proxy_bind,
            proxy_port=config.zap_proxy_port,
            proxy_advertised_host=config.zap_proxy_host,
        ),
    }


# Catalog used by the API (no worker-side configuration needed).
CATALOG: dict[ScannerName, type[Scanner]] = {
    ScannerName.DNS: DnsScanner,
    ScannerName.SUBDOMAINS: SubdomainScanner,
    ScannerName.TLS: TlsScanner,
    ScannerName.NMAP: NmapScanner,
    ScannerName.HTTP: HttpScanner,
    ScannerName.NUCLEI: NucleiScanner,
    ScannerName.ZAP: ZapScanner,
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
