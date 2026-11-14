"""Passive subdomain discovery from certificate transparency (crt.sh).

Only a third-party CT log is queried; the target is never contacted. Every name
is normalized and must be a subdomain of the authorized domain. Discovered names
are reported with provenance and first/last-seen timestamps, but are **not**
registered or scanned automatically: they may belong to third parties and need
their own asset registration and authorization.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, ClassVar, Final

import httpx

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
from sentinelx_security.scope.targets import (
    TargetError,
    is_subdomain_of,
    normalize_hostname,
)

DEFAULT_CRTSH_URL: Final = "https://crt.sh/"
MAX_RESPONSE_BYTES: Final = 20 * 1024 * 1024
MAX_SUBDOMAINS: Final = 5000


def extract_subdomains(entries: list[Mapping[str, Any]], domain: str) -> dict[str, dict[str, Any]]:
    """Map hostname → provenance for every valid subdomain of ``domain`` in CT entries."""
    found: dict[str, dict[str, Any]] = {}
    for entry in entries:
        names = str(entry.get("name_value", "")).splitlines()
        not_before = str(entry.get("not_before") or "") or None
        for raw_name in names:
            name = raw_name.strip().removeprefix("*.")
            try:
                host = normalize_hostname(name)
            except TargetError:
                continue
            if not is_subdomain_of(host, domain):
                continue
            record = found.setdefault(
                host,
                {
                    "hostname": host,
                    "sources": ["crt.sh"],
                    "first_seen": not_before,
                    "last_seen": not_before,
                    "certificates": 0,
                },
            )
            record["certificates"] += 1
            if not_before:
                if record["first_seen"] is None or not_before < record["first_seen"]:
                    record["first_seen"] = not_before
                if record["last_seen"] is None or not_before > record["last_seen"]:
                    record["last_seen"] = not_before
            if len(found) >= MAX_SUBDOMAINS:
                return found
    return found


class SubdomainScanner(Scanner):
    name: ClassVar[ScannerName] = ScannerName.SUBDOMAINS
    technique: ClassVar[Technique] = Technique.PASSIVE
    description: ClassVar[str] = "Passive subdomain discovery from certificate transparency logs."
    supported_asset_types = frozenset({AssetType.DOMAIN})

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_CRTSH_URL,
        transport: httpx.AsyncBaseTransport | None = None,
        enabled: bool = True,
    ) -> None:
        self._base_url = base_url
        self._transport = transport
        self._enabled = enabled

    async def execute(self, ctx: ScanContext) -> RawOutput:
        if not self._enabled:
            raise ScanError(
                "source_disabled", "Passive third-party sources are disabled by configuration."
            )
        domain = ctx.target.host
        async with httpx.AsyncClient(
            base_url=self._base_url,
            transport=self._transport,
            timeout=ctx.timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "SentinelX/0.4 (+passive CT lookup)"},
        ) as client:
            try:
                async with client.stream(
                    "GET", "/", params={"q": f"%.{domain}", "output": "json"}
                ) as response:
                    if response.status_code != httpx.codes.OK:
                        raise ScanError(
                            "source_unavailable",
                            "The certificate transparency source returned an error.",
                            retryable=True,
                        )
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_RESPONSE_BYTES:
                            raise ScanError(
                                "output_too_large", "The CT source returned too much data."
                            )
            except httpx.TimeoutException as exc:
                raise ScanError(
                    "timeout", "The certificate transparency source timed out.", retryable=True
                ) from exc
            except httpx.HTTPError as exc:
                raise ScanError(
                    "source_unavailable",
                    "The certificate transparency source is unreachable.",
                    retryable=True,
                ) from exc
        try:
            entries = json.loads(body.decode("utf-8")) if body.strip() else []
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ScanError("invalid_output", "The CT source returned malformed data.") from exc
        if not isinstance(entries, list):
            raise ScanError("invalid_output", "The CT source returned malformed data.")
        subdomains = extract_subdomains([e for e in entries if isinstance(e, dict)], domain)
        return RawOutput(
            data={"domain": domain, "subdomains": subdomains, "entries": len(entries)},
            tool_versions={"crt.sh": "api", "httpx": httpx.__version__},
        )

    def normalize_results(self, raw: RawOutput) -> list[Observation]:
        return [
            Observation(
                kind="discovered_subdomain",
                key=host,
                data={**record, "parent_domain": raw.data["domain"]},
            )
            for host, record in sorted(raw.data["subdomains"].items())
        ]

    def record_evidence(self, raw: RawOutput) -> list[Evidence]:
        names = sorted(raw.data["subdomains"])
        return [
            Evidence.bounded(
                "Certificate transparency summary",
                f"source: crt.sh\nentries: {raw.data['entries']}\n"
                f"unique subdomains: {len(names)}\n\n" + "\n".join(names),
            )
        ]
