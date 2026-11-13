"""Report data: one versioned JSON document, the single source for every format.

Everything comes from stored assessment data. AI commentary is included only from
analyses a person has reviewed, kept in its own section and labelled with its
provider, model, prompt version and reviewer. Scanner-derived text is included as
data (bounded); renderers must treat it as untrusted.
"""

from __future__ import annotations

import json
import uuid
from collections import Counter, defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AIAnalysis,
    Asset,
    AssetAuthorization,
    Cve,
    Finding,
    FindingOccurrence,
    Project,
    ScanJob,
)
from app.models.finding import SEVERITIES
from app.services.risk import project_posture

SCHEMA_VERSION: Final = "sentinelx-report/1.0"
MAX_FINDINGS: Final = 500
MAX_EVIDENCE_CHARS: Final = 1_000
MAX_OCCURRENCES: Final = 2
MAX_AI_ANALYSES: Final = 20
ACTIVE: Final = ("open", "acknowledged")
_PRIORITY: Final = {
    "critical": "Immediate",
    "high": "Immediate",
    "medium": "Short term",
    "low": "Planned",
    "info": "Optional",
}
# info=0 … critical=4: a larger rank is more severe.
_RANK: Final = {name: index for index, name in enumerate(SEVERITIES)}

METHODOLOGY: Final = (
    "Assets were assessed only within recorded, time-bound authorizations. Every scan "
    "was checked by a deny-by-default scope engine before it was queued and again, with "
    "fresh DNS resolution, immediately before execution; scanners connected only to the "
    "addresses approved by that decision. Scans used server-defined safe profiles in an "
    "isolated sandbox; no exploitation, brute force, denial-of-service or evasion "
    "techniques were used. Observations were normalized into findings by versioned, "
    "deterministic rules, correlated with NVD, CISA KEV and FIRST EPSS intelligence, and "
    "prioritized by a deterministic, explainable risk model."
)

STANDARD_LIMITATIONS: Final = (
    "Findings are produced by automated tools. Absence of a finding is not proof that an "
    "issue is absent; automated scanners produce false negatives.",
    "Findings with 'tentative' confidence (including CVE matches inferred from software "
    "versions) need manual confirmation before they are treated as confirmed.",
    "Results reflect the state of the assets at the scan dates listed in this report.",
    "Risk scores combine severity, confidence, asset context and threat intelligence; they "
    "support prioritization and do not replace business impact analysis.",
)


@dataclass(frozen=True, slots=True)
class ReportRequest:
    report_id: uuid.UUID
    project_id: uuid.UUID
    scope: str
    scan_job_id: uuid.UUID | None
    title: str
    format: str
    include_resolved: bool
    include_ai: bool
    include_evidence: bool
    generated_by: str | None


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _excerpt(observation: Any) -> str:
    text = json.dumps(observation, ensure_ascii=False, sort_keys=True, default=str)
    return text if len(text) <= MAX_EVIDENCE_CHARS else text[:MAX_EVIDENCE_CHARS] + "…"


def remediation_plan(active: Sequence[Finding]) -> list[dict[str, Any]]:
    """One action per rule, at the priority of its most severe finding, most urgent first."""
    plan: dict[str, dict[str, Any]] = {}
    for f in active:
        band = f.risk_band or f.severity
        entry = plan.setdefault(
            f.rule_id,
            {
                "action": f.remediation or f"Remediate: {f.title}",
                "rule_id": f.rule_id,
                "title": f.title,
                "band": band,
                "findings": [],
            },
        )
        entry["findings"].append(str(f.id))
        if _RANK.get(band, 0) > _RANK.get(entry["band"], 0):
            entry["band"] = band
    return sorted(
        (
            {
                "priority": _PRIORITY.get(e["band"], "Planned"),
                "band": e["band"],
                "action": e["action"],
                "rule_id": e["rule_id"],
                "title": e["title"],
                "affected": len(e["findings"]),
                "finding_ids": e["findings"],
            }
            for e in plan.values()
        ),
        key=lambda e: (-_RANK.get(e["band"], 0), -e["affected"], e["rule_id"]),
    )


async def _finding_ids_for_scan(session: AsyncSession, job_id: uuid.UUID) -> set[uuid.UUID]:
    rows = await session.execute(
        select(FindingOccurrence.finding_id).where(FindingOccurrence.scan_job_id == job_id)
    )
    return {r[0] for r in rows}


async def build_report(session: AsyncSession, request: ReportRequest) -> dict[str, Any]:
    project = await session.get(Project, request.project_id)
    if project is None:
        raise LookupError("Project not found.")
    now = datetime.now(UTC)
    limitations: list[str] = list(STANDARD_LIMITATIONS)

    # ------------------------------------------------------------- scans & assets
    scan_stmt = select(ScanJob).where(ScanJob.project_id == project.id)
    if request.scope == "scan":
        scan_stmt = scan_stmt.where(ScanJob.id == request.scan_job_id)
    scans: Sequence[ScanJob] = (
        (await session.execute(scan_stmt.order_by(ScanJob.created_at))).scalars().all()
    )
    if request.scope == "scan" and not scans:
        raise LookupError("Scan not found.")
    asset_stmt = select(Asset).where(Asset.project_id == project.id)
    if request.scope == "scan":
        asset_stmt = asset_stmt.where(Asset.id == scans[0].asset_id)
    assets: Sequence[Asset] = (
        (await session.execute(asset_stmt.order_by(Asset.value))).scalars().all()
    )
    asset_names = {a.id: a.value for a in assets}
    authorizations = (
        (
            await session.execute(
                select(AssetAuthorization)
                .where(AssetAuthorization.asset_id.in_(list(asset_names)))
                .order_by(AssetAuthorization.valid_from)
            )
        )
        .scalars()
        .all()
        if asset_names
        else []
    )

    # ------------------------------------------------------------- findings
    finding_stmt = select(Finding).where(Finding.project_id == project.id)
    if request.scope == "scan" and request.scan_job_id:
        finding_stmt = finding_stmt.where(
            Finding.id.in_(await _finding_ids_for_scan(session, request.scan_job_id))
        )
    if not request.include_resolved:
        finding_stmt = finding_stmt.where(Finding.status.in_(ACTIVE))
    findings: Sequence[Finding] = (
        (
            await session.execute(
                finding_stmt.order_by(
                    Finding.risk_score.desc().nulls_last(), Finding.last_seen_at.desc()
                ).limit(MAX_FINDINGS + 1)
            )
        )
        .scalars()
        .all()
    )
    if len(findings) > MAX_FINDINGS:
        findings = findings[:MAX_FINDINGS]
        limitations.append(
            f"Only the {MAX_FINDINGS} highest-risk findings are included in this report."
        )
    cve_ids = {f.cve_id for f in findings if f.cve_id}
    cves = (
        {c.id: c for c in (await session.execute(select(Cve).where(Cve.id.in_(cve_ids)))).scalars()}
        if cve_ids
        else {}
    )
    evidence: dict[uuid.UUID, list[dict[str, Any]]] = defaultdict(list)
    if request.include_evidence and findings:
        rows = (
            (
                await session.execute(
                    select(FindingOccurrence)
                    .where(FindingOccurrence.finding_id.in_([f.id for f in findings]))
                    .order_by(FindingOccurrence.observed_at.desc())
                )
            )
            .scalars()
            .all()
        )
        for occurrence in rows:
            if len(evidence[occurrence.finding_id]) < MAX_OCCURRENCES:
                evidence[occurrence.finding_id].append(
                    {
                        "observed_at": _iso(occurrence.observed_at),
                        "scan_job_id": str(occurrence.scan_job_id)
                        if occurrence.scan_job_id
                        else None,
                        "excerpt": _excerpt(occurrence.observation),
                    }
                )

    def cve_block(cve_id: str | None) -> dict[str, Any] | None:
        cve = cves.get(cve_id or "")
        if cve is None:
            return None
        return {
            "id": cve.id,
            "cvss_version": cve.cvss_version,
            "cvss_score": cve.cvss_score,
            "cvss_vector": cve.cvss_vector,
            "cisa_kev": cve.kev_added_on is not None,
            "kev_added_on": cve.kev_added_on.isoformat() if cve.kev_added_on else None,
            "epss_score": cve.epss_score,
            "source": "NVD",
        }

    finding_rows = [
        {
            "id": str(f.id),
            "title": f.title,
            "rule_id": f.rule_id,
            "source": f.source,
            "category": f.category,
            "detection": "automated",
            "severity": f.severity,
            "confidence": f.confidence,
            "status": f.status,
            "status_reason": f.status_reason,
            "risk_score": f.risk_score,
            "risk_band": f.risk_band,
            "risk_explanation": f.risk_explanation,
            "cwe": f.cwe,
            "cve": cve_block(f.cve_id),
            "asset": asset_names.get(f.asset_id, str(f.asset_id)),
            "location": f.location,
            "first_seen_at": _iso(f.first_seen_at),
            "last_seen_at": _iso(f.last_seen_at),
            "occurrence_count": f.occurrence_count,
            "description": f.description,
            "remediation": f.remediation,
            "references": list(f.references)[:10],
            "evidence": evidence.get(f.id, []),
        }
        for f in findings
    ]

    # ------------------------------------------------------------- distributions
    active = [f for f in findings if f.status in ACTIVE]
    by_severity = dict.fromkeys(SEVERITIES, 0) | dict(Counter(f.severity for f in active))
    by_band = dict.fromkeys(SEVERITIES, 0) | dict(Counter(f.risk_band or "info" for f in active))
    by_status = dict(Counter(f.status for f in findings))

    remediation = remediation_plan(active)

    # ------------------------------------------------------------- tool versions
    tools: dict[str, set[str]] = defaultdict(set)
    for job in scans:
        for tool, version in (job.tool_versions or {}).items():
            tools[str(tool)].add(str(version))
    scanners: dict[tuple[str, str], dict[str, Any]] = {}
    for job in scans:
        entry = scanners.setdefault(
            (job.scanner, job.technique),
            {"scanner": job.scanner, "technique": job.technique, "profiles": set(), "scans": 0},
        )
        entry["profiles"].add(job.profile)
        entry["scans"] += 1
    if not scans:
        limitations.append("No scans were run in this scope; the report reflects no test data.")
    if any(job.status != "completed" for job in scans):
        limitations.append(
            "Some scans did not complete; their targets may be only partially assessed."
        )

    # ------------------------------------------------------------- AI commentary
    commentary: list[dict[str, Any]] = []
    if request.include_ai:
        ai_stmt = select(AIAnalysis).where(
            AIAnalysis.project_id == project.id,
            AIAnalysis.status == "completed",
            AIAnalysis.reviewed_at.is_not(None),
        )
        if request.scope == "scan" and request.scan_job_id:
            subjects = [request.scan_job_id, *(f.id for f in findings)]
            ai_stmt = ai_stmt.where(AIAnalysis.subject_id.in_(subjects))
        else:
            ai_stmt = ai_stmt.where(
                AIAnalysis.kind.in_(("executive_summary", "technical_summary", "finding_analysis"))
            )
        analyses = (
            (
                await session.execute(
                    ai_stmt.order_by(AIAnalysis.completed_at.desc()).limit(MAX_AI_ANALYSES * 3)
                )
            )
            .scalars()
            .all()
        )
        seen: set[tuple[str, uuid.UUID]] = set()
        for analysis in analyses:
            key = (analysis.kind, analysis.subject_id)
            if key in seen or len(commentary) >= MAX_AI_ANALYSES:
                continue  # newest reviewed analysis per subject only
            seen.add(key)
            commentary.append(
                {
                    "analysis_id": str(analysis.id),
                    "kind": analysis.kind,
                    "subject_id": str(analysis.subject_id),
                    "provider": analysis.provider,
                    "model": analysis.model,
                    "prompt_version": analysis.prompt_version,
                    "generated_at": _iso(analysis.completed_at),
                    "reviewed_by": analysis.reviewed_by_email,
                    "reviewed_at": _iso(analysis.reviewed_at),
                    "label": (
                        "AI-generated commentary (advisory)"
                        if analysis.provider == "anthropic"
                        else "Deterministic summary (no AI model used)"
                    ),
                    "output": analysis.output,
                }
            )
        if commentary:
            limitations.append(
                "AI commentary is advisory, was reviewed by the person named with it, and is "
                "kept separate from automated findings and evidence."
            )

    # ------------------------------------------------------------- executive summary
    posture = await project_posture(session, project.id)
    kev = sum(1 for f in active if (block := cve_block(f.cve_id)) and block["cisa_kev"])
    urgent = by_band.get("critical", 0) + by_band.get("high", 0)
    statement = (
        f"As of {now.date().isoformat()}, {len(active)} active finding(s) affect "
        f"{len(assets)} asset(s) in scope; {urgent} rated critical or high risk"
        + (f", and {kev} involve vulnerabilities known to be exploited (CISA KEV)" if kev else "")
        + f". The project's risk posture is {posture['score']:.0f}/100 ({posture['band']})."
        if active
        else (
            f"As of {now.date().isoformat()}, no active findings were recorded for the "
            f"{len(assets)} asset(s) in scope."
        )
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "report": {
            "id": str(request.report_id),
            "title": request.title,
            "scope": request.scope,
            "scan_job_id": str(request.scan_job_id) if request.scan_job_id else None,
            "format": request.format,
            "generated_at": now.isoformat(),
            "generated_by": request.generated_by,
            "parameters": {
                "include_resolved": request.include_resolved,
                "include_ai": request.include_ai,
                "include_evidence": request.include_evidence,
            },
        },
        "project": {
            "id": str(project.id),
            "name": project.name,
            "description": project.description,
        },
        "executive_summary": {
            "statement": statement,
            "posture": posture if request.scope == "project" else None,
            "active_findings": len(active),
            "critical_or_high": urgent,
            "known_exploited": kev,
        },
        "scope": {
            "assets": [
                {
                    "id": str(a.id),
                    "type": a.type,
                    "value": a.value,
                    "criticality": a.criticality,
                    "exposure": a.exposure,
                    "status": a.status,
                }
                for a in assets
            ],
            "authorizations": [
                {
                    "asset": asset_names.get(a.asset_id, str(a.asset_id)),
                    "reference": a.reference,
                    "organization": a.organization,
                    "authorized_by": a.authorized_by,
                    "valid_from": _iso(a.valid_from),
                    "valid_until": _iso(a.valid_until),
                    "allow_active": a.allow_active,
                    "allow_intrusive": a.allow_intrusive,
                    "revoked_at": _iso(a.revoked_at),
                }
                for a in authorizations
            ],
        },
        "methodology": {
            "statement": METHODOLOGY,
            "scanners": [
                {**e, "profiles": sorted(e["profiles"])}
                for e in sorted(scanners.values(), key=lambda e: e["scanner"])
            ],
        },
        "scans": [
            {
                "id": str(job.id),
                "asset": asset_names.get(job.asset_id, str(job.asset_id)),
                "target": job.target,
                "scanner": job.scanner,
                "profile": job.profile,
                "technique": job.technique,
                "status": job.status,
                "requested_at": _iso(job.created_at),
                "started_at": _iso(job.started_at),
                "finished_at": _iso(job.finished_at),
                "error_code": job.error_code,
            }
            for job in scans
        ],
        "tool_versions": {tool: sorted(versions) for tool, versions in sorted(tools.items())},
        "severity_distribution": {
            "by_severity": by_severity,
            "by_risk_band": by_band,
            "by_status": by_status,
        },
        "findings": finding_rows,
        "remediation_plan": remediation,
        "ai_commentary": commentary,
        "limitations": limitations,
    }
