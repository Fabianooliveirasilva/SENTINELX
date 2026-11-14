"""Deterministic analyses, used whenever the model is not.

They are built only from the context items, with the same schema and the same
basis labels as model output, so the platform behaves identically without an AI
provider — it just explains less.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from app.ai.context import AnalysisContext, ContextItem
from app.ai.schemas import Action, AnalysisOutput, Claim, Section

FALLBACK_REASONS: Final = {
    "ai_disabled": "AI analysis is disabled on this platform.",
    "ai_not_configured": "The AI provider has no API key configured.",
    "budget_exceeded": "The project's daily AI token budget has been used.",
    "queue_unavailable": "The AI worker queue is unavailable.",
    "timeout": "The AI provider did not answer in time.",
    "rate_limited": "The AI provider is rate limiting requests.",
    "connection_error": "The AI provider could not be reached.",
    "api_error": "The AI provider returned an error.",
    "refused": "The AI provider declined this request.",
    "truncated": "The AI response was cut off before it was complete.",
    "invalid_output": "The AI response did not match the required format.",
}

_PRIORITY: Final = {"critical": "immediate", "high": "immediate", "medium": "short_term"}
_LIMITATION: Final = (
    "Generated deterministically from the assessment data; no AI model was used ({reason})."
)


def _basis(item: ContextItem) -> str:
    return "confirmed_evidence" if item.confirmed else "scanner_hypothesis"


def _finding_claim(item: ContextItem) -> Claim:
    d = item.data
    band = d.get("risk_band") or d.get("severity")
    return Claim(
        text=(
            f"{d['title']} ({d['severity']} severity, {d['confidence']} confidence, "
            f"risk {band}) at {d['location']}."
        ),
        basis=_basis(item),  # type: ignore[arg-type]
        references=[item.ref],
    )


def _intel_claims(items: list[ContextItem]) -> list[Claim]:
    claims = []
    for item in items:
        d = item.data
        parts = [f"{d['cve_id']}: CVSS {d.get('cvss_score') or 'n/a'}"]
        if d.get("cisa_kev"):
            parts.append("listed in CISA KEV (known exploited)")
        if d.get("epss_score") is not None:
            parts.append(f"EPSS {float(d['epss_score']):.3f}")
        claims.append(
            Claim(text="; ".join(parts) + ".", basis="external_intelligence", references=[item.ref])
        )
    return claims


def _actions(findings: list[ContextItem]) -> list[Action]:
    actions = []
    for item in findings[:10]:
        d = item.data
        remediation = d.get("rule_remediation") or "Review and remediate this finding."
        actions.append(
            Action(
                action=remediation,
                priority=_PRIORITY.get(d.get("risk_band") or d["severity"], "long_term"),  # type: ignore[arg-type]
                rationale=f"Addresses {d['title']} ({d.get('risk_band') or d['severity']}).",
                references=[item.ref],
            )
        )
    return actions


def _of(context: AnalysisContext, kind: str) -> list[ContextItem]:
    return [item for item in context.items if item.kind == kind]


def _finding(context: AnalysisContext) -> tuple[str, str, list[Section]]:
    finding = _of(context, "finding")[0]
    d = finding.data
    sections = [
        Section(heading="What was found", claims=[_finding_claim(finding)]),
    ]
    if d.get("description"):
        sections[0].claims.append(
            Claim(text=d["description"], basis=_basis(finding), references=[finding.ref])  # type: ignore[arg-type]
        )
    intel = _of(context, "intelligence")
    if intel:
        sections.append(Section(heading="Threat intelligence", claims=_intel_claims(intel)))
    risk = _of(context, "risk")
    if risk and risk[0].data.get("explanation"):
        sections.append(
            Section(
                heading="Why it matters",
                claims=[
                    Claim(
                        text=risk[0].data["explanation"],
                        basis="ai_recommendation"
                        if not finding.confirmed
                        else "confirmed_evidence",
                        references=[risk[0].ref, finding.ref],
                    )
                ],
            )
        )
    return d["title"], f"{d['severity'].capitalize()} finding: {d['title']}.", sections


def _scan(context: AnalysisContext) -> tuple[str, str, list[Section]]:
    scan = _of(context, "scan")[0]
    d = scan.data
    findings = _of(context, "finding")
    summary = (
        f"{d['scanner']}/{d['profile']} scan of {d['target']} {d['status']} with "
        f"{len(findings)} active finding(s) linked to it."
    )
    claims = [Claim(text=summary, basis="scanner_hypothesis", references=[scan.ref])]
    if d.get("error_code"):
        claims.append(
            Claim(
                text=f"The scan reported error '{d['error_code']}'.",
                basis="scanner_hypothesis",
                references=[scan.ref],
            )
        )
    sections = [Section(heading="Scan outcome", claims=claims)]
    if findings:
        sections.append(
            Section(heading="Key findings", claims=[_finding_claim(f) for f in findings[:10]])
        )
    return f"Scan summary: {d['target']}", summary, sections


def _comparison(context: AnalysisContext) -> tuple[str, str, list[Section]]:
    delta = _of(context, "delta")[0].data
    refs = {item.ref: item for item in _of(context, "finding")}
    summary = (
        f"{delta['new']['count']} new, {delta['resolved']['count']} resolved and "
        f"{delta['persisting']['count']} persisting finding(s) between the two scans."
    )
    sections = [
        Section(
            heading="What changed",
            claims=[Claim(text=summary, basis="scanner_hypothesis", references=["D1", "S1", "S2"])],
        )
    ]
    for name, heading in (("new", "New issues"), ("resolved", "Resolved issues")):
        items = [refs[r] for r in delta[name]["findings"] if r in refs]
        if items:
            sections.append(
                Section(heading=heading, claims=[_finding_claim(i) for i in items[:10]])
            )
    return "Scan comparison", summary, sections


def _project(context: AnalysisContext) -> tuple[str, str, list[Section]]:
    p = _of(context, "posture")[0].data
    counts = p["active_findings_by_risk_band"]
    score = float(p.get("risk_score") or 0)
    band = p.get("risk_band") or "info"
    if any(counts.values()):
        breakdown = ", ".join(f"{n} {name}" for name, n in counts.items() if n)
        summary = f"Project risk posture {score:.0f}/100 ({band}); {breakdown} active finding(s)."
    else:
        summary = "No active findings in this project."
    sections = [
        Section(
            heading="Overall posture",
            claims=[Claim(text=summary, basis="scanner_hypothesis", references=["P1"])],
        )
    ]
    findings = _of(context, "finding")
    if findings:
        sections.append(
            Section(heading="Top risks", claims=[_finding_claim(f) for f in findings[:10]])
        )
    intel = [i for i in _of(context, "intelligence") if i.data.get("cisa_kev")]
    if intel:
        sections.append(Section(heading="Known exploited", claims=_intel_claims(intel)))
    title = "Executive summary" if context.kind == "executive_summary" else "Technical summary"
    return title, summary, sections


_BUILDERS: Final[dict[str, Callable[[AnalysisContext], tuple[str, str, list[Section]]]]] = {
    "finding_analysis": _finding,
    "scan_summary": _scan,
    "scan_comparison": _comparison,
    "executive_summary": _project,
    "technical_summary": _project,
}


def deterministic(context: AnalysisContext, reason: str) -> AnalysisOutput:
    title, summary, sections = _BUILDERS[context.kind](context)
    findings: list[Any] = _of(context, "finding")
    return AnalysisOutput(
        title=title,
        summary=summary,
        sections=sections,
        recommended_actions=_actions(findings),
        investigation_steps=[],
        limitations=[_LIMITATION.format(reason=FALLBACK_REASONS.get(reason, reason))],
        confidence="medium",
    )
