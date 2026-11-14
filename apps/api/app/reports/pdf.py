"""PDF rendering of the report document with ReportLab.

ReportLab draws the document directly: nothing is fetched, no HTML/CSS engine is
involved, so report content cannot trigger network or file access. Its paragraph
mini-markup *does* understand tags such as ``<img src=…>`` and ``<a href=…>``, so
every string is XML-escaped before it becomes a Paragraph, and evidence excerpts
use ``Preformatted``, which does not parse markup at all.
"""

from __future__ import annotations

import html
import io
import re
import textwrap
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any, Final

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

NAVY: Final = colors.HexColor("#0B1B2E")
SLATE: Final = colors.HexColor("#4A5568")
RULE: Final = colors.HexColor("#CBD5E0")
SHADE: Final = colors.HexColor("#EDF2F7")
AI_SHADE: Final = colors.HexColor("#FFF8E6")
SEVERITY_COLORS: Final = {
    "critical": colors.HexColor("#9B1C1C"),
    "high": colors.HexColor("#C2410C"),
    "medium": colors.HexColor("#B7791F"),
    "low": colors.HexColor("#2B6CB0"),
    "info": colors.HexColor("#4A5568"),
}
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _dt(value: Any) -> str:
    """ISO timestamps as 'YYYY-MM-DD HH:MM UTC' for readability; other values unchanged."""
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return str(value)
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC)
    return parsed.strftime("%Y-%m-%d %H:%M UTC")


def _safe(value: Any) -> str:
    """Untrusted text → escaped Paragraph markup (no tags survive)."""
    text = "" if value is None else str(value)
    return html.escape(_CONTROL.sub("", text), quote=False).replace("\n", "<br/>")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=base["BodyText"], fontSize=9, leading=12)
    return {
        "title": ParagraphStyle(
            "title",
            parent=base["Title"],
            textColor=NAVY,
            fontSize=22,
            leading=26,
            alignment=TA_LEFT,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=body, textColor=SLATE, fontSize=11, leading=15
        ),
        "h1": ParagraphStyle(
            "h1", parent=base["Heading1"], textColor=NAVY, fontSize=15, spaceBefore=6, spaceAfter=6
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=base["Heading2"],
            textColor=NAVY,
            fontSize=11.5,
            spaceBefore=8,
            spaceAfter=3,
        ),
        "body": body,
        "small": ParagraphStyle("small", parent=body, fontSize=7.5, leading=9.5, textColor=SLATE),
        "cell": ParagraphStyle("cell", parent=body, fontSize=7.5, leading=9.5),
        "label": ParagraphStyle("label", parent=body, fontSize=8, leading=10, textColor=SLATE),
        "mono": ParagraphStyle("mono", parent=body, fontName="Courier", fontSize=6.8, leading=8.2),
    }


class _Doc:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        self.s = _styles()
        self.story: list[Flowable] = []

    # ----------------------------------------------------------------- helpers

    def p(self, text: Any, style: str = "body") -> Paragraph:
        return Paragraph(_safe(text), self.s[style])

    def heading(self, text: str, level: str = "h1") -> None:
        self.story.append(Paragraph(_safe(text), self.s[level]))

    def para(self, text: Any, style: str = "body") -> None:
        self.story.append(self.p(text, style))

    def table(
        self,
        header: Sequence[str],
        rows: Iterable[Sequence[Any]],
        widths: Sequence[float],
        severity_col: int | None = None,
    ) -> None:
        body = [[self.p(h, "label") for h in header]]
        styles: list[tuple[Any, ...]] = [
            ("BACKGROUND", (0, 0), (-1, 0), SHADE),
            ("LINEBELOW", (0, 0), (-1, 0), 0.6, NAVY),
            ("LINEBELOW", (0, 1), (-1, -1), 0.25, RULE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for r, row in enumerate(rows, 1):
            body.append([self.p(cell, "cell") for cell in row])
            if severity_col is not None:
                color = SEVERITY_COLORS.get(str(row[severity_col]).lower())
                if color is not None:
                    styles.append(("TEXTCOLOR", (severity_col, r), (severity_col, r), color))
        if len(body) == 1:
            self.para("None.", "small")
            return
        table = Table(body, colWidths=[w * mm for w in widths], repeatRows=1)
        table.setStyle(TableStyle(styles))
        self.story.append(table)

    def evidence(self, text: str) -> Preformatted:
        lines = [
            chunk
            for line in text.splitlines() or [""]
            for chunk in textwrap.wrap(line, 118) or [""]
        ]
        return Preformatted(
            "\n".join(_CONTROL.sub("", line) for line in lines[:40]), self.s["mono"]
        )

    # ----------------------------------------------------------------- sections

    def cover(self) -> None:
        report, project = self.data["report"], self.data["project"]
        self.story += [
            Spacer(1, 30 * mm),
            self.p("SentinelX — Security Assessment Report", "subtitle"),
            Spacer(1, 4 * mm),
            self.p(report["title"], "title"),
            Spacer(1, 6 * mm),
        ]
        rows = [
            ("Project", project["name"]),
            ("Scope", "Single scan" if report["scope"] == "scan" else "Whole project"),
            ("Generated", _dt(report["generated_at"])),
            ("Generated by", report["generated_by"] or "SentinelX"),
            ("Report ID", report["id"]),
            ("Format", self.data["schema_version"]),
        ]
        self.table(("Field", "Value"), rows, (40, 120))
        self.story += [
            Spacer(1, 10 * mm),
            self.p(
                "Confidential. This report describes an authorized security assessment of "
                "assets owned by, or tested with the written permission of, the organization "
                "named in the authorization references. It contains information about "
                "security weaknesses; distribute it on a need-to-know basis.",
                "small",
            ),
            PageBreak(),
        ]

    def executive(self) -> None:
        summary = self.data["executive_summary"]
        self.heading("1. Executive summary")
        self.para(summary["statement"])
        dist = self.data["severity_distribution"]["by_risk_band"]
        self.heading("Risk distribution (active findings)", "h2")
        self.table(
            ("Critical", "High", "Medium", "Low", "Info"),
            [[dist.get(k, 0) for k in ("critical", "high", "medium", "low", "info")]],
            (32, 32, 32, 32, 32),
        )
        top = [f for f in self.data["findings"] if f["status"] in ("open", "acknowledged")][:10]
        self.heading("Risk prioritization — top findings", "h2")
        self.table(
            ("Risk", "Score", "Finding", "Asset"),
            [
                (
                    f["risk_band"] or f["severity"],
                    f"{f['risk_score']:.0f}" if f["risk_score"] is not None else "—",
                    f["title"],
                    f["asset"],
                )
                for f in top
            ],
            (18, 14, 88, 50),
            severity_col=0,
        )

    def scope(self) -> None:
        scope = self.data["scope"]
        self.heading("2. Assessment scope")
        self.table(
            ("Asset", "Type", "Criticality", "Exposure", "Status"),
            [
                (a["value"], a["type"], a["criticality"], a["exposure"], a["status"])
                for a in scope["assets"]
            ],
            (70, 30, 24, 24, 22),
        )
        self.heading("Authorization references", "h2")
        self.table(
            ("Asset", "Reference", "Organization / authorized by", "Window", "Techniques"),
            [
                (
                    a["asset"],
                    a["reference"],
                    f"{a['organization']} — {a['authorized_by']}",
                    f"{_dt(a['valid_from'])} → {_dt(a['valid_until'])}"
                    + (f" (revoked {_dt(a['revoked_at'])})" if a["revoked_at"] else ""),
                    "passive"
                    + (", active" if a["allow_active"] else "")
                    + (", intrusive" if a["allow_intrusive"] else ""),
                )
                for a in scope["authorizations"]
            ],
            (36, 24, 40, 48, 22),
        )

    def methodology(self) -> None:
        method = self.data["methodology"]
        self.heading("3. Methodology")
        self.para(method["statement"])
        self.heading("Scanners used", "h2")
        self.table(
            ("Scanner", "Technique", "Profiles", "Scans"),
            [
                (m["scanner"], m["technique"], ", ".join(m["profiles"]), m["scans"])
                for m in method["scanners"]
            ],
            (40, 30, 80, 20),
        )
        self.heading("Scan dates", "h2")
        self.table(
            ("Target", "Scanner / profile", "Status", "Started", "Finished"),
            [
                (
                    s["target"],
                    f"{s['scanner']}/{s['profile']}",
                    s["status"] + (f" ({s['error_code']})" if s["error_code"] else ""),
                    _dt(s["started_at"]),
                    _dt(s["finished_at"]),
                )
                for s in self.data["scans"]
            ],
            (50, 30, 26, 32, 32),
        )

    def findings(self) -> None:
        self.story.append(PageBreak())
        self.heading("4. Findings")
        dist = self.data["severity_distribution"]
        self.para(
            "All findings were detected by automated tools. By severity (active): "
            + ", ".join(f"{k} {v}" for k, v in dist["by_severity"].items())
            + ". By status: "
            + (", ".join(f"{k} {v}" for k, v in dist["by_status"].items()) or "none")
            + ".",
            "small",
        )
        for index, f in enumerate(self.data["findings"], 1):
            block: list[Flowable] = [
                Paragraph(f"4.{index} {_safe(f['title'])}", self.s["h2"]),
            ]
            facts = [
                (
                    "Risk",
                    f"{f['risk_band'] or '—'} ({f['risk_score']:.0f}/100)"
                    if f["risk_score"] is not None
                    else "—",
                ),
                ("Severity / confidence", f"{f['severity']} / {f['confidence']}"),
                (
                    "Status",
                    f["status"] + (f" — {f['status_reason']}" if f["status_reason"] else ""),
                ),
                ("Asset / location", f"{f['asset']} — {f['location']}"),
                ("Detection", f"{f['source']} ({f['rule_id']}), automated"),
                (
                    "Seen",
                    f"{_dt(f['first_seen_at'])} → {_dt(f['last_seen_at'])} "
                    f"({f['occurrence_count']} sightings)",
                ),
            ]
            if f["cwe"]:
                facts.append(("CWE", f"CWE-{f['cwe']}"))
            if f["cve"]:
                c = f["cve"]
                facts.append(
                    (
                        "CVE (NVD)",
                        f"{c['id']} — CVSS {c['cvss_score'] or 'n/a'} {c['cvss_vector'] or ''}"
                        + ("; listed in CISA KEV" if c["cisa_kev"] else "")
                        + (f"; EPSS {c['epss_score']:.3f}" if c["epss_score"] is not None else ""),
                    )
                )
            table = Table(
                [[self.p(k, "label"), self.p(v, "cell")] for k, v in facts],
                colWidths=[38 * mm, 132 * mm],
            )
            table.setStyle(
                TableStyle(
                    [
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE),
                    ]
                )
            )
            block.append(table)
            self.story.append(KeepTogether(block))
            if f["description"]:
                self.story += [self.p("Description", "label"), self.p(f["description"])]
            if f["risk_explanation"]:
                self.story += [self.p("Why this risk", "label"), self.p(f["risk_explanation"])]
            if f["remediation"]:
                self.story += [self.p("Remediation", "label"), self.p(f["remediation"])]
            for ev in f["evidence"]:
                self.story += [
                    self.p(
                        "Technical evidence (untrusted tool output, observed "
                        f"{_dt(ev['observed_at'])})",
                        "label",
                    ),
                    self.evidence(ev["excerpt"]),
                ]
            if f["references"]:
                self.story.append(self.p("References: " + " · ".join(f["references"]), "small"))

    def remediation(self) -> None:
        self.heading("5. Remediation recommendations")
        self.table(
            ("Priority", "Action", "Issue", "Affected"),
            [
                (r["priority"], r["action"], r["title"], r["affected"])
                for r in self.data["remediation_plan"]
            ],
            (22, 86, 46, 16),
        )

    def ai(self) -> None:
        commentary = self.data["ai_commentary"]
        if not commentary:
            return
        self.story.append(PageBreak())
        self.heading("6. AI commentary (advisory)")
        self.para(
            "The following commentary was generated by an AI model or by the deterministic "
            "fallback, reviewed by the named person, and is kept separate from the automated "
            "findings above. Each statement is labelled with its basis; references point to "
            "items of the assessment data used for that analysis.",
            "small",
        )
        self.story.append(Spacer(1, 3 * mm))
        for item in commentary:
            output = item["output"] or {}
            header = (
                f"{item['label']} — {item['kind'].replace('_', ' ')}; "
                f"{item['model'] or 'no model'}, {item['prompt_version']}; "
                f"reviewed by {item['reviewed_by']} on {_dt(item['reviewed_at'])}"
            )
            rows: list[list[Flowable]] = [
                [self.p(output.get("title", ""), "h2")],
                [self.p(header, "small")],
                [self.p(output.get("summary", ""))],
            ]
            for section in output.get("sections", []):
                rows.append([self.p(section["heading"], "label")])
                for claim in section["claims"]:
                    refs = f" [{', '.join(claim['references'])}]" if claim["references"] else ""
                    rows.append(
                        [
                            self.p(
                                f"[{claim['basis'].replace('_', ' ')}] {claim['text']}{refs}",
                                "cell",
                            )
                        ]
                    )
            for action in output.get("recommended_actions", []):
                rows.append(
                    [
                        self.p(
                            f"Recommended ({action['priority'].replace('_', ' ')}): "
                            f"{action['action']} — {action['rationale']}",
                            "cell",
                        )
                    ]
                )
            box = Table(rows, colWidths=[170 * mm])
            box.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), AI_SHADE),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#B7791F")),
                    ]
                )
            )
            self.story += [box, Spacer(1, 4 * mm)]

    def appendix(self) -> None:
        self.heading("7. Tool versions")
        self.table(
            ("Tool", "Versions"),
            [(tool, ", ".join(versions)) for tool, versions in self.data["tool_versions"].items()],
            (60, 110),
        )
        self.heading("8. Limitations")
        for item in self.data["limitations"]:
            self.para(f"• {item}")


def _page(canvas: Canvas, doc: SimpleDocTemplate, report_id: str) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(SLATE)
    width, _ = A4
    canvas.drawString(18 * mm, 10 * mm, f"SentinelX · Confidential · Report {report_id}")
    canvas.drawRightString(width - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def render_pdf(data: dict[str, Any], *, compress: bool = True) -> bytes:
    buffer = io.BytesIO()
    report_id = str(data["report"]["id"])
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=18 * mm,
        title=str(data["report"]["title"]),
        author="SentinelX",
        subject=f"Security assessment report — {data['project']['name']}",
        pageCompression=1 if compress else 0,
        # Deterministic metadata: no creation timestamps beyond the report's own.
        invariant=1,
    )
    builder = _Doc(data)
    builder.cover()
    builder.executive()
    builder.scope()
    builder.methodology()
    builder.findings()
    builder.remediation()
    builder.ai()
    builder.appendix()
    doc.build(
        builder.story,
        onFirstPage=lambda c, d: _page(c, d, report_id),
        onLaterPages=lambda c, d: _page(c, d, report_id),
    )
    return buffer.getvalue()
