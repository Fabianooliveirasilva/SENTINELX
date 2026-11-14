"""Server-side checks of model output against the context it was given.

Structured outputs guarantee the *shape*; these checks enforce the *meaning*:

* references must name context items; unknown references are removed;
* a claim's basis must be supported by what it cites (an ``external_intelligence``
  claim must cite an intelligence item, ``confirmed_evidence`` must cite evidence
  or a confirmed finding…); unsupported claims are downgraded to
  ``ai_recommendation`` so they are never presented as fact;
* claims and actions naming a CVE absent from the context are dropped
  (fabricated identifiers never reach the user);
* text is bounded.

Every correction is recorded as a warning on the analysis.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from app.ai.context import AnalysisContext, ContextItem, mentioned_cves
from app.ai.schemas import Action, AnalysisOutput, Claim, Section

MAX_FIELD: Final = 4_000
MAX_LIST: Final = 20


def _confirms(item: ContextItem) -> bool:
    return item.kind == "evidence" or (item.kind == "finding" and item.confirmed)


def _observes(item: ContextItem) -> bool:
    return item.kind in ("finding", "evidence", "scan", "delta")


def _informs(item: ContextItem) -> bool:
    return item.kind == "intelligence"


_SUPPORTS: Final[dict[str, Callable[[ContextItem], bool]]] = {
    "confirmed_evidence": _confirms,
    "scanner_hypothesis": _observes,
    "external_intelligence": _informs,
}


def _bound(text: str) -> str:
    text = text.strip()
    return text if len(text) <= MAX_FIELD else text[:MAX_FIELD] + "…"


class Validator:
    def __init__(self, context: AnalysisContext) -> None:
        self._items: dict[str, ContextItem] = context.refs()
        self._cves = context.cve_ids
        self.warnings: list[str] = []

    def _refs(self, refs: list[str], where: str) -> list[str]:
        known = [r for r in dict.fromkeys(r.strip() for r in refs) if r in self._items]
        unknown = sorted(set(refs) - set(known))
        if unknown:
            self.warnings.append(f"{where}: removed unknown references {', '.join(unknown)}.")
        return known[:MAX_LIST]

    def _fabricated(self, text: str, where: str) -> bool:
        invented = mentioned_cves([text]) - self._cves
        if invented:
            self.warnings.append(
                f"{where}: dropped text naming CVEs not in the assessment data "
                f"({', '.join(sorted(invented))})."
            )
        return bool(invented)

    def claim(self, claim: Claim, where: str) -> Claim | None:
        if self._fabricated(claim.text, where):
            return None
        refs = self._refs(claim.references, where)
        basis = claim.basis
        supported = _SUPPORTS.get(basis)
        if supported is not None and not any(supported(self._items[r]) for r in refs):
            self.warnings.append(
                f"{where}: basis '{basis}' is not supported by the cited items; "
                "shown as an AI recommendation."
            )
            basis = "ai_recommendation"
        return Claim(text=_bound(claim.text), basis=basis, references=refs)

    def action(self, action: Action, where: str) -> Action | None:
        if self._fabricated(f"{action.action} {action.rationale}", where):
            return None
        return Action(
            action=_bound(action.action),
            priority=action.priority,
            rationale=_bound(action.rationale),
            references=self._refs(action.references, where),
        )

    def output(self, output: AnalysisOutput) -> AnalysisOutput:
        sections = []
        for s_index, section in enumerate(output.sections[:MAX_LIST], 1):
            claims = [
                c
                for c_index, claim in enumerate(section.claims[:MAX_LIST], 1)
                if (c := self.claim(claim, f"section {s_index} claim {c_index}")) is not None
            ]
            sections.append(Section(heading=_bound(section.heading), claims=claims))
        actions = [
            a
            for index, action in enumerate(output.recommended_actions[:MAX_LIST], 1)
            if (a := self.action(action, f"action {index}")) is not None
        ]
        steps = [
            _bound(s)
            for index, s in enumerate(output.investigation_steps[:MAX_LIST], 1)
            if not self._fabricated(s, f"investigation step {index}")
        ]
        summary = output.summary
        if self._fabricated(summary, "summary"):
            summary = "The summary referred to data outside this assessment and was removed."
        return AnalysisOutput(
            title=_bound(output.title),
            summary=_bound(summary),
            sections=sections,
            recommended_actions=actions,
            investigation_steps=steps,
            limitations=[_bound(x) for x in output.limitations[:MAX_LIST]],
            confidence=output.confidence,
        )


def restore(output: AnalysisOutput, context: AnalysisContext) -> AnalysisOutput:
    """Put the withheld values back for display (stored results are internal)."""
    restore_text = context.pseudonyms.restore
    return AnalysisOutput(
        title=restore_text(output.title),
        summary=restore_text(output.summary),
        sections=[
            Section(
                heading=restore_text(s.heading),
                claims=[
                    Claim(text=restore_text(c.text), basis=c.basis, references=c.references)
                    for c in s.claims
                ],
            )
            for s in output.sections
        ],
        recommended_actions=[
            Action(
                action=restore_text(a.action),
                priority=a.priority,
                rationale=restore_text(a.rationale),
                references=a.references,
            )
            for a in output.recommended_actions
        ],
        investigation_steps=[restore_text(s) for s in output.investigation_steps],
        limitations=[restore_text(x) for x in output.limitations],
        confidence=output.confidence,
    )
