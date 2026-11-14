"""PDF rendering: valid output, deterministic, and inert against markup in data."""

from __future__ import annotations

import copy
import re
from typing import Any

from app.reports.pdf import render_pdf

HOSTILE = (
    '<img src="/etc/passwd" width="10" height="10"/> <a href="https://evil.example.com">x</a> '
    '<font color="red">t</font> & \x00\x07 </para>'
)


def _data() -> dict[str, Any]:
    finding = {
        "id": "f1",
        "title": f"Banner {HOSTILE}",
        "rule_id": "http.cleartext_http",
        "source": "http",
        "category": "http",
        "detection": "automated",
        "severity": "medium",
        "confidence": "confirmed",
        "status": "open",
        "status_reason": None,
        "risk_score": 55.0,
        "risk_band": "medium",
        "risk_explanation": "Medium risk.",
        "cwe": 319,
        "cve": {
            "id": "CVE-2021-41773",
            "cvss_version": "3.1",
            "cvss_score": 7.5,
            "cvss_vector": "AV:N",
            "cisa_kev": True,
            "kev_added_on": "2021-11-03",
            "epss_score": 0.97,
            "source": "NVD",
        },
        "asset": "93.184.215.14",
        "location": "93.184.215.14 http://x/",
        "first_seen_at": "2026-11-12T10:00:00+00:00",
        "last_seen_at": "2026-11-12T11:00:00+00:00",
        "occurrence_count": 2,
        "description": HOSTILE,
        "remediation": "Use HTTPS.",
        "references": ["https://owasp.org/"],
        "evidence": [
            {
                "observed_at": "2026-11-12T11:00:00+00:00",
                "scan_job_id": None,
                "excerpt": HOSTILE * 20,
            }
        ],
    }
    return {
        "schema_version": "sentinelx-report/1.0",
        "report": {
            "id": "00000000-0000-4000-8000-000000000001",
            "title": "Assessment",
            "scope": "project",
            "scan_job_id": None,
            "format": "pdf",
            "generated_at": "2026-11-13T00:00:00+00:00",
            "generated_by": "analyst@example.com",
            "parameters": {},
        },
        "project": {"id": "p", "name": "Acme", "description": ""},
        "executive_summary": {
            "statement": "One active finding.",
            "posture": None,
            "active_findings": 1,
            "critical_or_high": 0,
            "known_exploited": 1,
        },
        "scope": {
            "assets": [
                {
                    "id": "a",
                    "type": "ip_address",
                    "value": "93.184.215.14",
                    "criticality": "high",
                    "exposure": "external",
                    "status": "active",
                }
            ],
            "authorizations": [
                {
                    "asset": "93.184.215.14",
                    "reference": "SOW-1",
                    "organization": "Acme",
                    "authorized_by": "Jane",
                    "valid_from": "2026-11-01",
                    "valid_until": "2026-12-01",
                    "allow_active": True,
                    "allow_intrusive": False,
                    "revoked_at": None,
                }
            ],
        },
        "methodology": {
            "statement": "Safe profiles.",
            "scanners": [
                {"scanner": "http", "technique": "active", "profiles": ["default"], "scans": 1}
            ],
        },
        "scans": [
            {
                "id": "s",
                "asset": "93.184.215.14",
                "target": "http://93.184.215.14/",
                "scanner": "http",
                "profile": "default",
                "technique": "active",
                "status": "completed",
                "requested_at": "x",
                "started_at": "2026-11-12T10:00:00+00:00",
                "finished_at": "2026-11-12T10:01:00+00:00",
                "error_code": None,
            }
        ],
        "tool_versions": {"httpx": ["0.28.1"]},
        "severity_distribution": {
            "by_severity": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
            "by_risk_band": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
            "by_status": {"open": 1},
        },
        "findings": [finding] * 3,
        "remediation_plan": [
            {
                "priority": "Short term",
                "band": "medium",
                "action": "Use HTTPS.",
                "rule_id": "r",
                "title": "t",
                "affected": 1,
                "finding_ids": ["f1"],
            }
        ],
        "ai_commentary": [
            {
                "analysis_id": "x",
                "kind": "executive_summary",
                "subject_id": "p",
                "provider": "anthropic",
                "model": "claude-opus-5-5",
                "prompt_version": "executive_summary@1.0.0+system@1.0.0",
                "generated_at": "2026-11-12",
                "reviewed_by": "lead@example.com",
                "reviewed_at": "2026-11-12",
                "label": "AI-generated commentary (advisory)",
                "output": {
                    "title": "Summary",
                    "summary": HOSTILE,
                    "sections": [
                        {
                            "heading": "H",
                            "claims": [
                                {
                                    "text": HOSTILE,
                                    "basis": "scanner_hypothesis",
                                    "references": ["F1"],
                                }
                            ],
                        }
                    ],
                    "recommended_actions": [
                        {
                            "action": "Patch",
                            "priority": "immediate",
                            "rationale": "KEV",
                            "references": ["I1"],
                        }
                    ],
                },
            }
        ],
        "limitations": ["Automated."],
    }


def test_pdf_is_valid_and_markup_in_data_stays_text() -> None:
    pdf = render_pdf(_data(), compress=False)
    assert pdf.startswith(b"%PDF-")
    assert pdf.rstrip().endswith(b"%%EOF")
    # Tags in untrusted text are rendered literally: no image, link or font change.
    assert b"/Subtype /Image" not in pdf
    assert b"/Subtype /Link" not in pdf
    assert b"/URI" not in pdf
    text = pdf.decode("latin-1")
    assert "etc/passwd" in text  # shown as text…
    assert re.search(r"\\\(|&lt;|<img", text) or "img src" in text  # …as characters
    assert "AI-generated commentary" in text
    assert "SOW-1" in text


def test_pdf_rendering_is_deterministic() -> None:
    data = _data()
    assert render_pdf(data) == render_pdf(copy.deepcopy(data))


def test_remediation_plan_puts_the_most_severe_first() -> None:
    import uuid

    from app.models import Finding
    from app.reports.builder import remediation_plan

    def finding(rule: str, band: str) -> Finding:
        return Finding(
            id=uuid.uuid4(),
            rule_id=rule,
            title=rule,
            severity=band,
            risk_band=band,
            remediation=f"fix {rule}",
        )

    plan = remediation_plan(
        [
            finding("info.rule", "info"),
            finding("high.rule", "high"),
            finding("mixed.rule", "low"),
            finding("mixed.rule", "critical"),
            finding("medium.rule", "medium"),
        ]
    )
    assert [p["rule_id"] for p in plan] == ["mixed.rule", "high.rule", "medium.rule", "info.rule"]
    assert [p["priority"] for p in plan] == ["Immediate", "Immediate", "Short term", "Optional"]
    assert plan[0]["band"] == "critical"  # the group takes its most severe finding's band
    assert plan[0]["affected"] == 2


def test_timestamps_are_readable() -> None:
    from app.reports.pdf import _dt

    assert _dt("2026-11-13T00:36:30.037785+00:00") == "2026-11-13 00:36 UTC"
    assert _dt(None) == "—"
    assert _dt("not a date") == "not a date"
