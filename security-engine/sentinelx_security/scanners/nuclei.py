"""Nuclei with a curated, version-pinned template set.

Safety properties:

* Templates come only from the directory baked into the scanner image at a pinned
  release (checksum-verified at build time); updates are disabled at runtime.
* Only template *directories* on an allowlist are loaded, only the ``http``
  protocol is enabled, and templates tagged intrusive/dos/fuzz/brute-force/
  exploit-style are excluded on top of that.
* Out-of-band interaction (interactsh) is disabled: no third-party callbacks.
* All traffic goes through the in-process :class:`EgressGuard`, which only admits
  the authorized host/port and connects to the pinned addresses.
* Rate limit, concurrency, per-request timeout, no retries, overall timeout with
  process-group kill, bounded output. The tool gets a minimal environment.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, ClassVar, Final

from sentinelx_security.egress import EgressGuard, EgressPolicy
from sentinelx_security.scanners.base import (
    Evidence,
    Observation,
    RawOutput,
    ScanContext,
    ScanError,
    Scanner,
    ScannerName,
)
from sentinelx_security.scanners.nmap import ProcessRunner, SubprocessRunner
from sentinelx_security.scope import AssetType, Technique
from sentinelx_security.scope.targets import parse_target

DEFAULT_TEMPLATES_DIR: Final = "/opt/nuclei-templates"
MAX_MATCHES: Final = 1000
MAX_LINE_BYTES: Final = 64 * 1024

# Template directories (relative to the pinned template release) per profile.
PROFILE_TEMPLATES: Final[Mapping[str, tuple[str, ...]]] = {
    "baseline": (
        "http/misconfiguration",
        "http/exposures/configs",
        "http/exposures/files",
        "http/exposures/logs",
        "http/technologies",
    ),
    "exposures": (
        "http/exposures",
        "http/exposed-panels",
        "http/misconfiguration",
    ),
}
PROFILE_DESCRIPTIONS: Final[Mapping[str, str]] = {
    "baseline": "Misconfigurations, exposed config/log files and technology detection",
    "exposures": "Baseline plus exposed panels and broader sensitive-file exposures",
}
EXCLUDED_TAGS: Final = (
    "intrusive",
    "dos",
    "fuzz",
    "fuzzing",
    "brute-force",
    "bruteforce",
    "default-login",
    "rce",
    "sqli",
    "xss",
    "lfi",
    "ssrf",
    "oast",
    "exploit",
    "kev",
    "takeover",
)
FORBIDDEN_FLAGS: Final = frozenset(
    {"-l", "-list", "-tu", "-w", "-workflows", "-code", "-dast", "-fuzz", "-headless", "-file"}
)


def build_argv(
    binary: str, profile: str, url: str, proxy_url: str, templates_dir: str
) -> list[str]:
    if profile not in PROFILE_TEMPLATES:
        raise ScanError("invalid_profile", "Unknown Nuclei profile.")
    argv = [
        binary,
        "-target",
        url,
        "-jsonl",
        "-silent",
        "-no-color",
        "-disable-update-check",
        "-no-interactsh",
        "-omit-raw",
        "-no-stdin",
        "-protocol-type",
        "http",
        "-exclude-tags",
        ",".join(EXCLUDED_TAGS),
        "-rate-limit",
        "20",
        "-concurrency",
        "5",
        "-bulk-size",
        "5",
        "-timeout",
        "8",
        "-retries",
        "0",
        "-max-host-error",
        "20",
        "-proxy",
        proxy_url,
        "-header",
        "User-Agent: SentinelX/0.5 (+authorized assessment)",
    ]
    for directory in PROFILE_TEMPLATES[profile]:
        argv += ["-templates", f"{templates_dir.rstrip('/')}/{directory}"]
    return argv


def _strings(value: object, limit: int = 20) -> list[str]:
    if isinstance(value, str):
        return [value[:500]]
    if isinstance(value, list):
        return [str(v)[:500] for v in value[:limit] if isinstance(v, str | int)]
    return []


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def parse_jsonl(output: bytes) -> list[dict[str, Any]]:
    """Parse Nuclei JSONL defensively (untrusted, size-bounded, schema-checked)."""
    matches: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip() or len(line) > MAX_LINE_BYTES:
            continue
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(record, dict) or not isinstance(record.get("template-id"), str):
            continue
        info = _mapping(record.get("info"))
        classification = _mapping(info.get("classification"))
        matches.append(
            {
                "template_id": record["template-id"][:200],
                "matcher_name": str(record.get("matcher-name") or "")[:200] or None,
                "matched_at": str(record.get("matched-at") or "")[:2048],
                "type": str(record.get("type") or "")[:20],
                "name": str(info.get("name") or "")[:300],
                "severity": str(info.get("severity") or "info").lower()[:16],
                "description": str(info.get("description") or "")[:4000],
                "remediation": str(info.get("remediation") or "")[:4000],
                "references": _strings(info.get("reference")),
                "tags": _strings(info.get("tags")),
                "cve_ids": _strings(classification.get("cve-id")),
                "cwe_ids": _strings(classification.get("cwe-id")),
                "extracted_results": _strings(record.get("extracted-results")),
            }
        )
        if len(matches) >= MAX_MATCHES:
            break
    return matches


class NucleiScanner(Scanner):
    name: ClassVar[ScannerName] = ScannerName.NUCLEI
    technique: ClassVar[Technique] = Technique.ACTIVE
    description: ClassVar[str] = (
        "Curated, version-pinned Nuclei templates (no intrusive, fuzzing or exploit templates)."
    )
    profiles: ClassVar[Mapping[str, str]] = PROFILE_DESCRIPTIONS
    default_profile: ClassVar[str] = "baseline"
    supported_asset_types = frozenset(
        {
            AssetType.DOMAIN,
            AssetType.SUBDOMAIN,
            AssetType.IP_ADDRESS,
            AssetType.WEB_APPLICATION,
            AssetType.API_ENDPOINT,
        }
    )

    def __init__(
        self,
        *,
        binary: str = "nuclei",
        templates_dir: str = DEFAULT_TEMPLATES_DIR,
        version: str = "unknown",
        templates_version: str = "unknown",
        runner: ProcessRunner | None = None,
    ) -> None:
        self._binary = binary
        self._templates_dir = templates_dir
        self._version = version
        self._templates_version = templates_version
        self._runner = runner or SubprocessRunner()

    @classmethod
    def target_for(cls, asset_type: AssetType, value: str) -> str:
        super().target_for(asset_type, value)
        target = parse_target(value)
        return value if target.is_url else f"https://{target.host_for_netloc}/"

    async def execute(self, ctx: ScanContext) -> RawOutput:
        if not ctx.target.is_url:
            raise ScanError("unsupported_target", "Nuclei needs a URL target.")
        if not ctx.pinned_addresses:
            raise ScanError("no_addresses", "No authorized addresses to connect to.")
        guard = EgressGuard(EgressPolicy.for_target(ctx.target, ctx.pinned_addresses))
        async with guard:
            host, port = await guard.start()
            url = f"{ctx.target.origin}{ctx.target.path or '/'}"
            argv = build_argv(
                self._binary, ctx.profile, url, f"http://{host}:{port}", self._templates_dir
            )
            result = await self._runner.run(argv, timeout_seconds=ctx.timeout_seconds, env=None)
        if result.returncode != 0:
            raise ScanError("tool_failed", "Nuclei exited with an error.")
        return RawOutput(
            data={
                "url": url,
                "profile": ctx.profile,
                "templates": list(PROFILE_TEMPLATES[ctx.profile]),
                "matches": parse_jsonl(result.stdout),
                "egress": guard.stats.summary(),
            },
            tool_versions={"nuclei": self._version, "nuclei-templates": self._templates_version},
        )

    def normalize_results(self, raw: RawOutput) -> list[Observation]:
        observations: list[Observation] = []
        for match in raw.data["matches"]:
            suffix = f":{match['matcher_name']}" if match["matcher_name"] else ""
            observations.append(
                Observation(
                    kind="template_match",
                    key=f"{match['template_id']}{suffix} {match['matched_at']}",
                    data=match,
                )
            )
        return observations

    def record_evidence(self, raw: RawOutput) -> list[Evidence]:
        egress = raw.data["egress"]
        lines = [
            f"target: {raw.data['url']}",
            f"profile: {raw.data['profile']}",
            "template directories: " + ", ".join(raw.data["templates"]),
            f"excluded tags: {', '.join(EXCLUDED_TAGS)}",
            f"egress connections: {egress['connections']}, denied: {egress['denied_total']}",
        ]
        lines += [f"denied destination: {d}" for d in egress["denied_destinations"]]
        lines += [
            f"match: {m['template_id']} [{m['severity']}] {m['matched_at']}"
            for m in raw.data["matches"]
        ]
        return [Evidence.bounded("Nuclei run summary", "\n".join(lines))]
