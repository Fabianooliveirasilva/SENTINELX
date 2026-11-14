"""Context sent to the model: minimal, pseudonymized, labelled, deterministic.

* **Minimal.** Only the fields an analysis needs; evidence is truncated; at most a
  bounded number of findings per request.
* **Pseudonymized.** Asset values, hostnames, IP addresses and e-mail addresses
  are replaced by placeholders (``[HOST-1]``…) before anything leaves the
  platform, and restored only when the stored result is displayed.
* **Redacted.** Credential-looking values (authorization headers, cookies, API
  keys, passwords) are removed from untrusted text.
* **Labelled.** Every item has a ``ref`` the model must cite, a ``kind`` that
  determines which claim bases it can support, and ``untrusted: true`` when its
  text comes from a scanned system.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import InvalidRequestError, NotFoundError
from app.models import (
    Asset,
    Cve,
    Finding,
    FindingOccurrence,
    ScanJob,
    SecurityEvent,
)
from app.models.finding import SEVERITIES

MAX_TEXT: Final = 1_500
MAX_EVIDENCE: Final = 2_000
MAX_FINDINGS: Final = 25
MAX_OCCURRENCES: Final = 3
ACTIVE: Final = ("open", "acknowledged")

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api[_-]?key|"
    r"access[_-]?token|token|password|passwd|secret)\b(\s*[:=]\s*)([^\s,;\"']+(?:\s+[^\s,;\"']+)?)"
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/?#\"'<>]+")
_PLACEHOLDER = re.compile(r"\[(HOST|IP|EMAIL)-\d+\]")


def _clean(value: str, limit: int) -> str:
    value = _CONTROL.sub("", value)
    return value if len(value) <= limit else value[:limit] + "…[truncated]"


class Pseudonymizer:
    """Replaces identifying values by stable placeholders, and back."""

    def __init__(self) -> None:
        self._forward: dict[str, str] = {}
        self._counters: Counter[str] = Counter()

    def _token(self, kind: str, value: str) -> str:
        key = value.lower()
        if key not in self._forward:
            self._counters[kind] += 1
            self._forward[key] = f"[{kind}-{self._counters[kind]}]"
        return self._forward[key]

    def register_target(self, value: str) -> None:
        """Assets, scan targets and URLs: hostnames and IPs become placeholders."""
        host = urlsplit(value).hostname if "://" in value else value.strip("[]")
        if not host:
            return
        try:
            ipaddress.ip_address(host)
        except ValueError:
            self._token("HOST", host)
        else:
            self._token("IP", host)

    def apply(self, text: str) -> str:
        # E-mail addresses first: their domain must not be replaced on its own,
        # which would leave the local part behind.
        text = _EMAIL.sub(lambda m: self._token("EMAIL", m.group(0)), text)
        # Any host named in a URL is withheld too, not only registered assets.
        for match in _URL.finditer(text):
            self.register_target(match.group(0))
        # Longest known values first, so "www.example.com" wins over "example.com".
        for value in sorted(self._forward, key=len, reverse=True):
            if self._forward[value].startswith("[HOST"):
                text = re.sub(
                    rf"(?i)(?<![\w.-]){re.escape(value)}(?![\w-])", self._forward[value], text
                )
        text = _IPV4.sub(lambda m: self._ip(m.group(0)), text)
        return _IPV6.sub(lambda m: self._ip(m.group(0)), text)

    def _ip(self, candidate: str) -> str:
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        return self._token("IP", candidate)

    def restore(self, text: str) -> str:
        reverse = {token: value for value, token in self._forward.items()}
        return _PLACEHOLDER.sub(lambda m: reverse.get(m.group(0), m.group(0)), text)

    @property
    def count(self) -> int:
        return len(self._forward)


@dataclass(slots=True)
class ContextItem:
    ref: str
    kind: str  # finding / evidence / intelligence / risk / scan / asset / delta / posture
    data: dict[str, Any]
    untrusted: bool = False
    confirmed: bool = False  # findings only: confidence == "confirmed"

    def render(self) -> dict[str, Any]:
        rendered = {"ref": self.ref, "kind": self.kind, **self.data}
        if self.untrusted:
            rendered["untrusted"] = True
        return rendered


@dataclass(slots=True)
class AnalysisContext:
    kind: str
    items: list[ContextItem]
    pseudonyms: Pseudonymizer
    cve_ids: set[str] = field(default_factory=set)

    def rendered(self) -> list[dict[str, Any]]:
        return [item.render() for item in self.items]

    def refs(self) -> dict[str, ContextItem]:
        return {item.ref: item for item in self.items}

    def digest(self, prompt_version: str, model: str) -> str:
        payload = json.dumps(
            {"kind": self.kind, "prompt": prompt_version, "model": model, "items": self.rendered()},
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def summary(self) -> dict[str, Any]:
        """What was sent, without the content (stored with the analysis)."""
        return {
            "items": dict(Counter(item.kind for item in self.items)),
            "refs": [item.ref for item in self.items],
            "untrusted_items": sum(item.untrusted for item in self.items),
            "pseudonymized_values": self.pseudonyms.count,
            "cves": sorted(self.cve_ids),
        }


# --------------------------------------------------------------------- sanitizing


def _untrusted(value: Any, limit: int, pseudonyms: Pseudonymizer) -> Any:
    """Recursively clean scanner-derived data: redact, pseudonymize, bound."""
    if isinstance(value, str):
        value = _SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", value)
        return pseudonyms.apply(_clean(value, limit))
    if isinstance(value, Mapping):
        return {str(k)[:100]: _untrusted(v, limit, pseudonyms) for k, v in list(value.items())[:50]}
    if isinstance(value, list | tuple):
        return [_untrusted(v, limit, pseudonyms) for v in list(value)[:50]]
    return value


def _text(value: str | None, pseudonyms: Pseudonymizer, limit: int = MAX_TEXT) -> str:
    return pseudonyms.apply(_clean(value or "", limit))


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


# --------------------------------------------------------------------- items


def _asset_item(asset: Asset, pseudonyms: Pseudonymizer) -> ContextItem:
    pseudonyms.register_target(asset.value)
    return ContextItem(
        "A1",
        "asset",
        {
            "type": asset.type,
            "value": pseudonyms.apply(asset.value),
            "criticality": asset.criticality,
            "exposure": asset.exposure,
        },
    )


def _finding_item(ref: str, finding: Finding, pseudonyms: Pseudonymizer) -> ContextItem:
    return ContextItem(
        ref,
        "finding",
        {
            "title": _text(finding.title, pseudonyms, 300),
            "rule_id": finding.rule_id,
            "source": finding.source,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "status": finding.status,
            "cwe": finding.cwe,
            "cve_id": finding.cve_id,
            "location": _text(finding.location, pseudonyms, 300),
            # Rule descriptions and remediation come from SentinelX's own rule set.
            "description": _text(finding.description, pseudonyms),
            "rule_remediation": _text(finding.remediation, pseudonyms),
            "risk_score": finding.risk_score,
            "risk_band": finding.risk_band,
            "first_seen_at": _iso(finding.first_seen_at),
            "last_seen_at": _iso(finding.last_seen_at),
            "occurrence_count": finding.occurrence_count,
        },
        confirmed=finding.confidence == "confirmed",
    )


def _cve_item(ref: str, cve: Cve, pseudonyms: Pseudonymizer) -> ContextItem:
    return ContextItem(
        ref,
        "intelligence",
        {
            "cve_id": cve.id,
            "source": "NVD",
            "description": _text(cve.description, pseudonyms),
            "cvss_version": cve.cvss_version,
            "cvss_score": cve.cvss_score,
            "cvss_vector": cve.cvss_vector,
            "cvss_severity": cve.cvss_severity,
            "cwes": list(cve.cwes)[:5],
            "published_at": _iso(cve.published_at),
            "cisa_kev": cve.kev_added_on is not None,
            "kev_added_on": cve.kev_added_on.isoformat() if cve.kev_added_on else None,
            "kev_ransomware_campaign_use": cve.kev_ransomware,
            "epss_score": cve.epss_score,
            "epss_percentile": cve.epss_percentile,
        },
    )


async def _finding_items(
    session: AsyncSession,
    findings: Sequence[Finding],
    pseudonyms: Pseudonymizer,
    *,
    start: int = 1,
) -> tuple[list[ContextItem], set[str]]:
    items = [_finding_item(f"F{i}", f, pseudonyms) for i, f in enumerate(findings, start)]
    cve_ids = {f.cve_id for f in findings if f.cve_id}
    cves = (
        (await session.execute(select(Cve).where(Cve.id.in_(cve_ids)))).scalars().all()
        if cve_ids
        else []
    )
    items += [_cve_item(f"I{i}", cve, pseudonyms) for i, cve in enumerate(cves, 1)]
    return items, cve_ids


async def _active_findings(
    session: AsyncSession, *conditions: Any, limit: int = MAX_FINDINGS
) -> Sequence[Finding]:
    return (
        (
            await session.execute(
                select(Finding)
                .where(*conditions)
                .order_by(Finding.risk_score.desc().nulls_last(), Finding.last_seen_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )


# --------------------------------------------------------------------- builders


async def finding_context(
    session: AsyncSession, project_id: uuid.UUID, finding_id: uuid.UUID
) -> AnalysisContext:
    finding = (
        await session.execute(
            select(Finding).where(Finding.id == finding_id, Finding.project_id == project_id)
        )
    ).scalar_one_or_none()
    if finding is None:
        raise NotFoundError("Finding not found.")
    pseudonyms = Pseudonymizer()
    asset = await session.get(Asset, finding.asset_id)
    items: list[ContextItem] = [_asset_item(asset, pseudonyms)] if asset else []
    finding_items, cve_ids = await _finding_items(session, [finding], pseudonyms)
    items += finding_items
    occurrences = (
        (
            await session.execute(
                select(FindingOccurrence)
                .where(FindingOccurrence.finding_id == finding.id)
                .order_by(FindingOccurrence.observed_at.desc())
                .limit(MAX_OCCURRENCES)
            )
        )
        .scalars()
        .all()
    )
    for i, occurrence in enumerate(occurrences, 1):
        items.append(
            ContextItem(
                f"E{i}",
                "evidence",
                {
                    "of": "F1",
                    "observed_at": _iso(occurrence.observed_at),
                    "observation": _untrusted(occurrence.observation, MAX_EVIDENCE, pseudonyms),
                },
                untrusted=True,
            )
        )
    if finding.risk_score is not None:
        items.append(
            ContextItem(
                "R1",
                "risk",
                {
                    "of": "F1",
                    "score": finding.risk_score,
                    "band": finding.risk_band,
                    "model_version": finding.risk_model_version,
                    "explanation": _text(finding.risk_explanation, pseudonyms),
                    "factors": finding.risk_factors[:10],
                },
            )
        )
    return AnalysisContext("finding_analysis", items, pseudonyms, cve_ids)


def _scan_item(ref: str, job: ScanJob, pseudonyms: Pseudonymizer) -> ContextItem:
    pseudonyms.register_target(job.target)
    return ContextItem(
        ref,
        "scan",
        {
            "scanner": job.scanner,
            "profile": job.profile,
            "technique": job.technique,
            "target": pseudonyms.apply(job.target),
            "status": job.status,
            "error_code": job.error_code,
            "started_at": _iso(job.started_at),
            "finished_at": _iso(job.finished_at),
            "tool_versions": dict(job.tool_versions or {}),
            # Counts by observation kind and attention flag: derived, not raw output.
            "summary": _untrusted(job.summary or {}, MAX_TEXT, pseudonyms),
        },
    )


async def _scan(session: AsyncSession, project_id: uuid.UUID, job_id: uuid.UUID) -> ScanJob:
    job = (
        await session.execute(
            select(ScanJob).where(ScanJob.id == job_id, ScanJob.project_id == project_id)
        )
    ).scalar_one_or_none()
    if job is None:
        raise NotFoundError("Scan not found.")
    return job


async def _scan_finding_ids(session: AsyncSession, job_id: uuid.UUID) -> set[uuid.UUID]:
    rows = await session.execute(
        select(FindingOccurrence.finding_id).where(FindingOccurrence.scan_job_id == job_id)
    )
    return {r[0] for r in rows}


async def scan_context(
    session: AsyncSession, project_id: uuid.UUID, job_id: uuid.UUID
) -> AnalysisContext:
    job = await _scan(session, project_id, job_id)
    if job.status not in ("completed", "failed"):
        raise InvalidRequestError("Only finished scans can be summarized.")
    pseudonyms = Pseudonymizer()
    asset = await session.get(Asset, job.asset_id)
    items: list[ContextItem] = [_asset_item(asset, pseudonyms)] if asset else []
    items.append(_scan_item("S1", job, pseudonyms))
    ids = await _scan_finding_ids(session, job.id)
    findings = await _active_findings(session, Finding.id.in_(ids)) if ids else []
    finding_items, cve_ids = await _finding_items(session, findings, pseudonyms)
    return AnalysisContext("scan_summary", items + finding_items, pseudonyms, cve_ids)


async def comparison_context(
    session: AsyncSession, project_id: uuid.UUID, job_id: uuid.UUID, other_id: uuid.UUID
) -> AnalysisContext:
    first, second = (
        await _scan(session, project_id, job_id),
        await _scan(session, project_id, other_id),
    )
    if first.id == second.id:
        raise InvalidRequestError("Choose two different scans to compare.")
    if first.asset_id != second.asset_id:
        raise InvalidRequestError("Only scans of the same asset can be compared.")
    if first.status != "completed" or second.status != "completed":
        raise InvalidRequestError("Only completed scans can be compared.")
    earlier, later = sorted((first, second), key=lambda j: j.created_at)
    pseudonyms = Pseudonymizer()
    asset = await session.get(Asset, earlier.asset_id)
    items: list[ContextItem] = [_asset_item(asset, pseudonyms)] if asset else []
    items += [_scan_item("S1", earlier, pseudonyms), _scan_item("S2", later, pseudonyms)]
    before, after = (
        await _scan_finding_ids(session, earlier.id),
        await _scan_finding_ids(session, later.id),
    )
    groups = {"new": after - before, "resolved": before - after, "persisting": before & after}
    everything = set().union(*groups.values())
    findings = await _active_findings(session, Finding.id.in_(everything), limit=MAX_FINDINGS * 2)
    finding_items, cve_ids = await _finding_items(session, findings, pseudonyms)
    ref_of = {f.id: f"F{i}" for i, f in enumerate(findings, 1)}
    items.append(
        ContextItem(
            "D1",
            "delta",
            {
                "earlier_scan": "S1",
                "later_scan": "S2",
                **{
                    name: {
                        "count": len(ids),
                        "findings": sorted(ref_of[i] for i in ids if i in ref_of),
                    }
                    for name, ids in groups.items()
                },
            },
        )
    )
    return AnalysisContext("scan_comparison", items + finding_items, pseudonyms, cve_ids)


async def project_context(
    session: AsyncSession, project_id: uuid.UUID, kind: str
) -> AnalysisContext:
    pseudonyms = Pseudonymizer()
    counts = dict.fromkeys(SEVERITIES, 0)
    rows = await session.execute(
        select(Finding.risk_band, func.count())
        .where(Finding.project_id == project_id, Finding.status.in_(ACTIVE))
        .group_by(Finding.risk_band)
    )
    for band, n in rows:
        counts[band or "info"] = counts.get(band or "info", 0) + int(n)
    statuses = {
        s: int(n)
        for s, n in await session.execute(
            select(Finding.status, func.count())
            .where(Finding.project_id == project_id)
            .group_by(Finding.status)
        )
    }
    assets = await session.execute(
        select(Asset.type, Asset.exposure, func.count())
        .where(Asset.project_id == project_id, Asset.status == "active")
        .group_by(Asset.type, Asset.exposure)
    )
    since = datetime.now(UTC) - timedelta(days=30)
    scans = {
        s: int(n)
        for s, n in await session.execute(
            select(ScanJob.status, func.count())
            .where(ScanJob.project_id == project_id, ScanJob.created_at >= since)
            .group_by(ScanJob.status)
        )
    }
    events = {
        s: int(n)
        for s, n in await session.execute(
            select(SecurityEvent.severity, func.count())
            .where(
                SecurityEvent.project_id == project_id,
                SecurityEvent.occurred_at >= datetime.now(UTC) - timedelta(days=7),
            )
            .group_by(SecurityEvent.severity)
        )
    }
    from app.services.risk import project_posture  # local: avoids an import cycle

    posture = await project_posture(session, project_id)
    findings = await _active_findings(
        session, Finding.project_id == project_id, Finding.status.in_(ACTIVE), limit=15
    )
    finding_items, cve_ids = await _finding_items(session, findings, pseudonyms)
    kev = sum(
        1 for item in finding_items if item.kind == "intelligence" and item.data.get("cisa_kev")
    )
    items = [
        ContextItem(
            "P1",
            "posture",
            {
                "risk_score": posture.get("score"),
                "risk_band": posture.get("band"),
                "active_findings_by_risk_band": counts,
                "findings_by_status": statuses,
                "assets": [{"type": t, "exposure": e, "count": int(n)} for t, e, n in assets],
                "scans_last_30_days_by_status": scans,
                "events_last_7_days_by_severity": events,
                "known_exploited_cves_in_top_findings": kev,
                "top_findings": [item.ref for item in finding_items if item.kind == "finding"],
            },
        ),
        *finding_items,
    ]
    return AnalysisContext(kind, items, pseudonyms, cve_ids)


async def build_context(
    session: AsyncSession,
    *,
    kind: str,
    project_id: uuid.UUID,
    subject_id: uuid.UUID,
    parameters: Mapping[str, Any],
) -> AnalysisContext:
    if kind == "finding_analysis":
        return await finding_context(session, project_id, subject_id)
    if kind == "scan_summary":
        return await scan_context(session, project_id, subject_id)
    if kind == "scan_comparison":
        return await comparison_context(
            session, project_id, subject_id, uuid.UUID(str(parameters["compare_with"]))
        )
    if kind in ("executive_summary", "technical_summary"):
        return await project_context(session, project_id, kind)
    raise InvalidRequestError(f"Unknown analysis kind {kind!r}.")


def mentioned_cves(texts: Iterable[str]) -> set[str]:
    return {m.upper() for text in texts for m in re.findall(r"(?i)\bCVE-\d{4}-\d{4,7}\b", text)}
