"""Nmap port and service discovery with fixed, server-side profiles.

Safety properties:

* The argument vector is built only from a whitelisted profile and canonical IP
  addresses produced by the scope engine (pinned addresses). User input never
  reaches the command line, and no shell is involved.
* TCP connect scan (``-sT``) as an unprivileged user: no raw sockets, no
  ``NET_RAW`` capability, no OS fingerprinting, no stealth/evasion options.
* No NSE script selection. ``-sV --version-light`` only runs version probes
  (and Nmap's built-in ``version`` category), never intrusive categories.
* Bounded rate, retries, per-host timeout, total timeout and output size; on
  timeout the whole process group is killed.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import signal
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar, Final, Protocol

from defusedxml import DefusedXmlException, ElementTree

from sentinelx_security.scanners.base import (
    Evidence,
    Observation,
    RawOutput,
    ScanContext,
    ScanError,
    Scanner,
    ScannerName,
)
from sentinelx_security.scope import AssetType, Technique
from sentinelx_security.scope.targets import IPAddress

MAX_OUTPUT_BYTES: Final = 5 * 1024 * 1024

BASE_ARGUMENTS: Final = (
    "-sT",
    "-Pn",
    "-n",
    "--unprivileged",
    "--open",
    "-sV",
    "--version-light",
    "--max-retries",
    "2",
    "--host-timeout",
    "300s",
    "--max-rate",
    "100",
    "-oX",
    "-",
)

PROFILES: Final[Mapping[str, tuple[str, ...]]] = {
    "quick": ("--top-ports", "100"),
    "standard": ("--top-ports", "1000"),
    "web": ("-p", "80,443,8000,8008,8080,8443,8888"),
}

PROFILE_DESCRIPTIONS: Final[Mapping[str, str]] = {
    "quick": "Top 100 TCP ports with light service detection",
    "standard": "Top 1000 TCP ports with light service detection",
    "web": "Common web ports (80, 443, 8000, 8008, 8080, 8443, 8888)",
}

# Options that must never appear, even if the code above is changed carelessly.
FORBIDDEN_OPTIONS: Final = frozenset(
    {"--script", "-sC", "-A", "-O", "-sS", "-sU", "-D", "-S", "-f", "--spoof-mac", "--privileged"}
)


@dataclass(frozen=True, slots=True)
class ProcessResult:
    stdout: bytes
    stderr: bytes
    returncode: int


class ProcessRunner(Protocol):
    async def run(
        self, argv: Sequence[str], *, timeout_seconds: float, env: Mapping[str, str] | None
    ) -> ProcessResult: ...


class SubprocessRunner:
    async def run(
        self, argv: Sequence[str], *, timeout_seconds: float, env: Mapping[str, str] | None
    ) -> ProcessResult:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
            env={**os.environ, **env} if env else None,
            start_new_session=True,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            await process.wait()
            raise
        if len(stdout) > MAX_OUTPUT_BYTES:
            raise ScanError("output_too_large", "The scanner produced too much output.")
        return ProcessResult(stdout=stdout, stderr=stderr, returncode=process.returncode or 0)


def build_argv(binary: str, profile: str, addresses: Sequence[IPAddress]) -> list[str]:
    if profile not in PROFILES:
        raise ScanError("invalid_profile", f"Unknown Nmap profile {profile!r}.")
    if not addresses:
        raise ScanError("no_addresses", "No authorized addresses to scan.")
    versions = {ip.version for ip in addresses}
    if len(versions) != 1:
        raise ScanError("mixed_families", "IPv4 and IPv6 addresses must be scanned separately.")
    argv = [binary, *BASE_ARGUMENTS, *PROFILES[profile]]
    if versions == {6}:
        argv.append("-6")
    # Canonical text from ipaddress objects: cannot contain options or shell syntax.
    argv.extend(ipaddress.ip_address(str(ip)).compressed for ip in addresses)
    if FORBIDDEN_OPTIONS.intersection(argv):  # pragma: no cover - defensive invariant
        raise ScanError("forbidden_option", "Refusing to run a forbidden Nmap option.")
    return argv


def parse_nmap_xml(xml: bytes) -> dict[str, Any]:
    """Parse ``-oX`` output safely (defusedxml blocks entity expansion attacks)."""
    try:
        root = ElementTree.fromstring(xml)
    except (ElementTree.ParseError, DefusedXmlException) as exc:
        raise ScanError("invalid_output", "Nmap returned output that could not be parsed.") from exc
    hosts: list[dict[str, Any]] = []
    for host in root.iter("host"):
        address_el = host.find("address")
        if address_el is None:
            continue
        ports: list[dict[str, Any]] = []
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            ports.append(
                {
                    "port": int(port.get("portid", "0")),
                    "protocol": port.get("protocol", "tcp"),
                    "service": (service.get("name") if service is not None else None) or "unknown",
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                    "extrainfo": service.get("extrainfo") if service is not None else None,
                    "tunnel": service.get("tunnel") if service is not None else None,
                }
            )
        hosts.append({"address": address_el.get("addr"), "ports": ports})
    return {"version": root.get("version", "unknown"), "hosts": hosts}


class NmapScanner(Scanner):
    name: ClassVar[ScannerName] = ScannerName.NMAP
    technique: ClassVar[Technique] = Technique.ACTIVE
    description: ClassVar[str] = "TCP port discovery and service detection (Nmap, safe profiles)."
    profiles: ClassVar[Mapping[str, str]] = PROFILE_DESCRIPTIONS
    default_profile: ClassVar[str] = "quick"
    # Host-wide port discovery needs a host-level authorization: a web application,
    # API or service asset authorizes one origin/port, not every port on the host.
    supported_asset_types = frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS})

    def __init__(
        self,
        *,
        binary: str = "nmap",
        datadir: str | None = None,
        runner: ProcessRunner | None = None,
    ) -> None:
        self._binary = binary
        self._env = {"NMAPDIR": datadir} if datadir else None
        self._runner = runner or SubprocessRunner()

    async def execute(self, ctx: ScanContext) -> RawOutput:
        by_family: dict[int, list[IPAddress]] = {}
        for ip in ctx.pinned_addresses:
            by_family.setdefault(ip.version, []).append(ip)
        hosts: list[dict[str, Any]] = []
        raw_xml: list[str] = []
        version = "unknown"
        for addresses in by_family.values():
            argv = build_argv(self._binary, ctx.profile, addresses)
            result = await self._runner.run(
                argv, timeout_seconds=ctx.timeout_seconds, env=self._env
            )
            if result.returncode != 0:
                raise ScanError("tool_failed", "Nmap exited with an error.")
            parsed = parse_nmap_xml(result.stdout)
            version = parsed["version"]
            hosts.extend(parsed["hosts"])
            raw_xml.append(result.stdout.decode("utf-8", "replace"))
        return RawOutput(
            data={"hosts": hosts, "xml": raw_xml, "profile": ctx.profile},
            tool_versions={"nmap": version},
        )

    def normalize_results(self, raw: RawOutput) -> list[Observation]:
        observations: list[Observation] = []
        for host in raw.data["hosts"]:
            for port in host["ports"]:
                attention: list[str] = []
                if port["service"] in {"telnet", "ftp", "rlogin", "rsh"}:
                    attention.append("cleartext_service")
                if port["service"] in {"ms-sql-s", "mysql", "postgresql", "redis", "mongodb"}:
                    attention.append("database_exposed")
                observations.append(
                    Observation(
                        kind="open_port",
                        key=f"{host['address']}:{port['port']}/{port['protocol']}",
                        data={"address": host["address"], **port},
                        attention=tuple(attention),
                    )
                )
        return observations

    def record_evidence(self, raw: RawOutput) -> list[Evidence]:
        return [
            Evidence.bounded(f"nmap XML ({raw.data['profile']})", xml, "application/xml")
            for xml in raw.data["xml"]
        ]
