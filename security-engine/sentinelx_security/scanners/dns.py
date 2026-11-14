"""DNS analyzer (passive: queries go to resolvers, never to the target's hosts).

Collects A, AAAA, CNAME, MX, NS, TXT, CAA and SOA records and derives
email-security posture (SPF, DMARC) and CAA presence. Observations describe
what was seen; judging severity is the vulnerability phase's job.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any, ClassVar, Final, Protocol

import dns.asyncresolver
import dns.exception
import dns.resolver

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

RECORD_TYPES: Final = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA", "SOA")
MAX_RECORDS_PER_TYPE: Final = 100


class DnsQuery(Protocol):
    async def __call__(self, name: str, rdtype: str) -> list[str]: ...


class DnspythonQuery:
    def __init__(self, *, timeout_seconds: float = 5.0, nameservers: tuple[str, ...] = ()) -> None:
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.lifetime = timeout_seconds
        if nameservers:
            self._resolver.nameservers = list(nameservers)

    async def __call__(self, name: str, rdtype: str) -> list[str]:
        try:
            answer = await self._resolver.resolve(name, rdtype, search=False)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return []
        return [record.to_text() for record in answer][:MAX_RECORDS_PER_TYPE]


def _unquote_txt(value: str) -> str:
    # TXT records arrive as one or more quoted strings: "v=spf1 " "include:x -all"
    parts = [p for p in value.split('"') if p.strip()]
    return "".join(parts) if parts else value


def analyze_spf(txt_records: list[str]) -> dict[str, Any]:
    spf = [r for r in map(_unquote_txt, txt_records) if r.lower().startswith("v=spf1")]
    if not spf:
        return {"present": False, "record": None, "all_qualifier": None}
    record = spf[0]
    qualifier = next(
        (
            term[0] if term[0] in "+-~?" else "+"
            for term in record.split()
            if term.lstrip("+-~?") == "all"
        ),
        None,
    )
    return {"present": True, "record": record, "all_qualifier": qualifier, "multiple": len(spf) > 1}


def analyze_dmarc(txt_records: list[str]) -> dict[str, Any]:
    dmarc = [r for r in map(_unquote_txt, txt_records) if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return {"present": False, "record": None, "policy": None}
    tags = dict(part.strip().split("=", 1) for part in dmarc[0].split(";") if "=" in part)
    return {
        "present": True,
        "record": dmarc[0],
        "policy": tags.get("p", "").strip().lower() or None,
    }


class DnsScanner(Scanner):
    name: ClassVar[ScannerName] = ScannerName.DNS
    technique: ClassVar[Technique] = Technique.PASSIVE
    description: ClassVar[str] = "DNS records, SPF, DMARC and CAA posture (via resolvers)."
    supported_asset_types = frozenset({AssetType.DOMAIN, AssetType.SUBDOMAIN})

    def __init__(self, query: DnsQuery | None = None) -> None:
        self._query = query or DnspythonQuery()

    async def execute(self, ctx: ScanContext) -> RawOutput:
        host = ctx.target.host
        try:
            answers = await asyncio.gather(*(self._query(host, t) for t in RECORD_TYPES))
            dmarc = await self._query(f"_dmarc.{host}", "TXT")
        except dns.exception.Timeout as exc:
            raise ScanError("dns_timeout", "DNS queries timed out.", retryable=True) from exc
        except dns.exception.DNSException as exc:
            raise ScanError("dns_error", "DNS resolution failed.", retryable=True) from exc
        records: dict[str, list[str]] = dict(zip(RECORD_TYPES, answers, strict=True))
        return RawOutput(
            data={"host": host, "records": records, "dmarc": dmarc},
            tool_versions={"dnspython": dns.version.version},
        )

    def normalize_results(self, raw: RawOutput) -> list[Observation]:
        host: str = raw.data["host"]
        records: Mapping[str, list[str]] = raw.data["records"]
        observations = [
            Observation(
                kind="dns_record",
                key=f"{host} {rtype}",
                data={"host": host, "type": rtype, "values": values},
            )
            for rtype, values in records.items()
            if values
        ]
        if not any(records.values()):
            observations.append(
                Observation(
                    kind="dns_record",
                    key=f"{host} NONE",
                    data={"host": host, "type": "NONE", "values": []},
                    attention=("no_records",),
                )
            )

        spf = analyze_spf(records.get("TXT", []))
        dmarc = analyze_dmarc(raw.data["dmarc"])
        attention: list[str] = []
        if records.get("MX"):
            if not spf["present"]:
                attention.append("spf_missing")
            elif spf["all_qualifier"] in ("+", "?"):
                attention.append("spf_permissive")
            if not dmarc["present"]:
                attention.append("dmarc_missing")
            elif dmarc["policy"] == "none":
                attention.append("dmarc_policy_none")
        observations.append(
            Observation(
                kind="email_security",
                key=host,
                data={
                    "host": host,
                    "receives_mail": bool(records.get("MX")),
                    "spf": spf,
                    "dmarc": dmarc,
                },
                attention=tuple(attention),
            )
        )
        observations.append(
            Observation(
                kind="caa",
                key=host,
                data={
                    "host": host,
                    "present": bool(records.get("CAA")),
                    "records": records.get("CAA", []),
                },
                attention=() if records.get("CAA") else ("caa_missing",),
            )
        )
        return observations

    def record_evidence(self, raw: RawOutput) -> list[Evidence]:
        lines = [
            f"{raw.data['host']} {rtype} {v}"
            for rtype, values in raw.data["records"].items()
            for v in values
        ]
        lines += [f"_dmarc.{raw.data['host']} TXT {v}" for v in raw.data["dmarc"]]
        return [Evidence.bounded("DNS answers", "\n".join(lines) or "(no records)")]
