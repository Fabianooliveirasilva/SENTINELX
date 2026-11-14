"""Finding derivation: rule catalog integrity, mapping and stable identity."""

from __future__ import annotations

from typing import Any

from sentinelx_security.findings import (
    FLAG_RULES,
    RULES,
    Confidence,
    Severity,
    derive_findings,
)
from sentinelx_security.scanners.http import review_headers


def obs(kind: str, key: str, *attention: str, **data: Any) -> dict[str, Any]:
    return {"kind": kind, "key": key, "data": data, "attention": list(attention)}


def test_every_flag_maps_to_a_defined_rule() -> None:
    for mapping in FLAG_RULES.values():
        for rule_id in mapping.values():
            assert rule_id in RULES
    for rule in RULES.values():
        assert rule.title
        assert rule.description
        assert rule.remediation
        assert rule.id.split(".")[0] in {"tls", "http", "dns", "network"}


def test_http_header_flags_have_rules() -> None:
    attention, _ = review_headers({}, "http")
    for flag in attention:
        assert flag in FLAG_RULES["http_endpoint"], flag


def test_flags_become_findings_and_unknown_flags_are_ignored() -> None:
    findings = derive_findings(
        [
            obs("tls_endpoint", "1.2.3.4:443", "certificate_expired", "legacy_protocol_tlsv1_0"),
            obs("http_endpoint", "1.2.3.4 https://x/", "missing_hsts", "something_new"),
            obs("open_port", "1.2.3.4:23/tcp", "cleartext_service"),
            obs("dns_record", "x NONE", "no_records"),
        ]
    )
    by_rule = {f.rule_id: f for f in findings}
    assert set(by_rule) == {
        "tls.certificate_expired",
        "tls.legacy_protocol_tlsv1_0",
        "http.missing_hsts",
        "network.cleartext_service",
    }
    expired = by_rule["tls.certificate_expired"]
    assert expired.severity is Severity.HIGH
    assert expired.confidence is Confidence.CONFIRMED
    assert expired.key == "1.2.3.4:443"
    assert expired.category == "tls"
    assert expired.cwe == 298


def test_duplicates_within_a_scan_collapse() -> None:
    o = obs("http_endpoint", "k", "missing_csp")
    assert len(derive_findings([o, o])) == 1


def test_fingerprint_is_stable_and_scoped_to_the_asset() -> None:
    (a,) = derive_findings([obs("caa", "example.com", "caa_missing")])
    (b,) = derive_findings([obs("caa", "example.com", "caa_missing")])
    assert a.fingerprint("asset-1") == b.fingerprint("asset-1")
    assert a.fingerprint("asset-1") != a.fingerprint("asset-2")
    assert len(a.fingerprint("asset-1")) == 64


def test_zap_alerts_keep_their_own_scales() -> None:
    alert = obs(
        "web_alert",
        "10038 https://app.example.com/",
        name="Content Security Policy (CSP) Header Not Set",
        plugin_id="10038",
        risk_code="2",
        confidence_code="3",
        cwe_id="693",
        description="desc",
        solution="fix",
        reference="https://developer.mozilla.org/x\nnot-a-url",
    )
    false_positive = obs("web_alert", "k2", plugin_id="1", risk_code="3", confidence_code="0")
    (finding,) = derive_findings([alert, false_positive])
    assert finding.rule_id == "zap.10038"
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.CONFIRMED
    assert finding.cwe == 693
    assert finding.references == ("https://developer.mozilla.org/x",)


def test_nuclei_matches_are_firm_not_confirmed() -> None:
    (finding,) = derive_findings(
        [
            obs(
                "template_match",
                "git-config https://app.example.com/.git/config",
                template_id="git-config",
                name="Git Config Disclosure",
                severity="Medium",
                cwe_ids=["CWE-538"],
                references=["https://example.org/ref"],
            )
        ]
    )
    assert finding.rule_id == "nuclei.git-config"
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.FIRM
    assert finding.cwe == 538
