"""Deterministic derivation of findings from normalized scanner observations.

Observations are facts ("TLSv1.0 is accepted on 93.184.215.14:443"); findings are
security-relevant conclusions with a severity, a confidence, remediation and a
stable identity so repeated scans update rather than duplicate them.

Rules are pure data and versioned (``RULESET_VERSION``): the same observations
always produce the same findings. Third-party scanner verdicts (ZAP alerts,
Nuclei matches) are carried over with their own severity and confidence mapped
onto SentinelX scales — never upgraded.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

RULESET_VERSION: Final = "2026.11.1"
MAX_TEXT: Final = 4000


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    TENTATIVE = "tentative"
    FIRM = "firm"
    CONFIRMED = "confirmed"


@dataclass(frozen=True, slots=True)
class FindingRule:
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    confidence: Confidence = Confidence.FIRM
    cwe: int | None = None
    references: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FindingCandidate:
    rule_id: str
    key: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    description: str
    remediation: str
    cwe: int | None
    references: tuple[str, ...]
    observation: Mapping[str, Any] = field(default_factory=dict)

    def fingerprint(self, asset_id: str) -> str:
        """Stable identity: the same issue on the same asset and location."""
        material = "\x1f".join((asset_id, self.rule_id, self.key)).encode()
        return hashlib.sha256(material).hexdigest()


_OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
_MOZ_TLS = "https://wiki.mozilla.org/Security/Server_Side_TLS"

RULES: Final[Mapping[str, FindingRule]] = {
    rule.id: rule
    for rule in (
        # --- TLS --------------------------------------------------------------------
        FindingRule(
            "tls.certificate_expired",
            "Expired TLS certificate",
            Severity.HIGH,
            "The server presents a certificate whose validity period has ended; clients "
            "reject the connection or users are trained to ignore warnings.",
            "Renew the certificate and automate renewal (e.g. ACME).",
            Confidence.CONFIRMED,
            298,
        ),
        FindingRule(
            "tls.certificate_expiring_soon",
            "TLS certificate expires within 30 days",
            Severity.LOW,
            "The certificate will expire soon and cause an outage if not renewed.",
            "Renew the certificate before it expires and monitor expiry dates.",
            Confidence.CONFIRMED,
        ),
        FindingRule(
            "tls.self_signed_certificate",
            "Self-signed TLS certificate",
            Severity.MEDIUM,
            "The certificate is not issued by a trusted authority, so clients cannot "
            "authenticate the server and are exposed to interception.",
            "Use a certificate from a publicly trusted CA (or a managed internal PKI).",
            Confidence.CONFIRMED,
            295,
        ),
        FindingRule(
            "tls.self_signed_in_chain",
            "Untrusted certificate chain",
            Severity.MEDIUM,
            "The certificate chain contains a self-signed certificate that is not trusted.",
            "Serve a complete chain that ends in a publicly trusted root.",
            Confidence.CONFIRMED,
            295,
        ),
        FindingRule(
            "tls.untrusted_issuer",
            "TLS certificate issuer not trusted",
            Severity.MEDIUM,
            "The certificate chain cannot be validated against the system trust store "
            "(unknown issuer or missing intermediate certificates).",
            "Install the intermediate certificates or use a publicly trusted CA.",
            Confidence.CONFIRMED,
            295,
        ),
        FindingRule(
            "tls.hostname_mismatch",
            "TLS certificate does not match the hostname",
            Severity.MEDIUM,
            "The certificate is not valid for the name clients use to reach the service.",
            "Issue a certificate whose subject alternative names include the hostname.",
            Confidence.CONFIRMED,
            297,
        ),
        FindingRule(
            "tls.verification_failed",
            "TLS certificate verification failed",
            Severity.MEDIUM,
            "The certificate could not be verified by a standard TLS client.",
            "Review the certificate chain and validity with the verification detail.",
            Confidence.FIRM,
            295,
        ),
        FindingRule(
            "tls.weak_rsa_key",
            "Weak RSA key in TLS certificate",
            Severity.MEDIUM,
            "The certificate uses an RSA key shorter than 2048 bits.",
            "Reissue the certificate with an RSA key of at least 2048 bits or ECDSA P-256.",
            Confidence.CONFIRMED,
            326,
            (_MOZ_TLS,),
        ),
        FindingRule(
            "tls.weak_signature_algorithm",
            "Weak certificate signature algorithm",
            Severity.MEDIUM,
            "The certificate is signed with MD5 or SHA-1, which are not collision resistant.",
            "Reissue the certificate with a SHA-256 (or stronger) signature.",
            Confidence.CONFIRMED,
            327,
        ),
        FindingRule(
            "tls.legacy_protocol_tlsv1_0",
            "Legacy protocol TLS 1.0 accepted",
            Severity.MEDIUM,
            "TLS 1.0 is deprecated (RFC 8996) and has known weaknesses.",
            "Disable TLS 1.0 and 1.1; offer TLS 1.2 and 1.3 only.",
            Confidence.CONFIRMED,
            327,
            ("https://www.rfc-editor.org/rfc/rfc8996", _MOZ_TLS),
        ),
        FindingRule(
            "tls.legacy_protocol_tlsv1_1",
            "Legacy protocol TLS 1.1 accepted",
            Severity.MEDIUM,
            "TLS 1.1 is deprecated (RFC 8996).",
            "Disable TLS 1.0 and 1.1; offer TLS 1.2 and 1.3 only.",
            Confidence.CONFIRMED,
            327,
            ("https://www.rfc-editor.org/rfc/rfc8996", _MOZ_TLS),
        ),
        # --- HTTP -------------------------------------------------------------------
        FindingRule(
            "http.cleartext_http",
            "Web content served over cleartext HTTP",
            Severity.MEDIUM,
            "Traffic, including cookies and credentials, can be read or modified in transit.",
            "Serve the application over HTTPS and redirect HTTP to HTTPS.",
            Confidence.CONFIRMED,
            319,
        ),
        FindingRule(
            "http.missing_hsts",
            "Missing HTTP Strict-Transport-Security header",
            Severity.LOW,
            "Without HSTS, browsers may be downgraded to HTTP by an active attacker.",
            "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
            Confidence.FIRM,
            319,
            (_OWASP_HEADERS,),
        ),
        FindingRule(
            "http.missing_csp",
            "Missing Content-Security-Policy header",
            Severity.LOW,
            "A CSP limits the impact of cross-site scripting and content injection.",
            "Define a restrictive Content-Security-Policy (start with `default-src 'self'`).",
            Confidence.FIRM,
            693,
            (_OWASP_HEADERS,),
        ),
        FindingRule(
            "http.missing_clickjacking_protection",
            "Missing clickjacking protection",
            Severity.LOW,
            "The page may be framed by other sites (no X-Frame-Options or frame-ancestors).",
            "Send `Content-Security-Policy: frame-ancestors 'none'` (or X-Frame-Options).",
            Confidence.FIRM,
            1021,
            (_OWASP_HEADERS,),
        ),
        FindingRule(
            "http.missing_x_content_type_options",
            "Missing X-Content-Type-Options header",
            Severity.INFO,
            "Browsers may MIME-sniff responses into executable content types.",
            "Send `X-Content-Type-Options: nosniff`.",
            Confidence.FIRM,
            693,
            (_OWASP_HEADERS,),
        ),
        FindingRule(
            "http.missing_referrer_policy",
            "Missing Referrer-Policy header",
            Severity.INFO,
            "Full URLs (which may contain tokens) can leak to third parties via Referer.",
            "Send `Referrer-Policy: strict-origin-when-cross-origin` or stricter.",
            Confidence.FIRM,
            200,
            (_OWASP_HEADERS,),
        ),
        FindingRule(
            "http.version_disclosure",
            "Software version disclosed in HTTP headers",
            Severity.INFO,
            "Exact product versions help attackers select exploits.",
            "Remove or genericize Server / X-Powered-By headers.",
            Confidence.FIRM,
            200,
        ),
        # --- DNS / e-mail -----------------------------------------------------------
        FindingRule(
            "dns.spf_missing",
            "No SPF record for a mail-receiving domain",
            Severity.LOW,
            "Without SPF, receivers cannot tell which servers may send mail for the domain.",
            "Publish an SPF record that lists authorized senders and ends with `-all`.",
        ),
        FindingRule(
            "dns.spf_permissive",
            "Permissive SPF policy",
            Severity.MEDIUM,
            "The SPF record ends in `+all` or `?all`, so any server may send as the domain.",
            "End the SPF record with `-all` (or `~all` while migrating).",
        ),
        FindingRule(
            "dns.dmarc_missing",
            "No DMARC policy",
            Severity.LOW,
            "Without DMARC, spoofed mail using the domain is not rejected and not reported.",
            "Publish `_dmarc` with `p=quarantine` or `p=reject` and a reporting address.",
        ),
        FindingRule(
            "dns.dmarc_policy_none",
            "DMARC policy is monitoring only (p=none)",
            Severity.LOW,
            "Spoofed messages are reported but still delivered.",
            "Move the DMARC policy to `quarantine`, then `reject`.",
        ),
        FindingRule(
            "dns.caa_missing",
            "No CAA record",
            Severity.INFO,
            "Any public CA may issue certificates for the domain.",
            "Publish CAA records naming the CAs you use.",
        ),
        # --- Network ----------------------------------------------------------------
        FindingRule(
            "network.cleartext_service",
            "Cleartext remote-access or file-transfer service exposed",
            Severity.MEDIUM,
            "Telnet, FTP, rlogin or rsh transmit credentials without encryption.",
            "Disable the service or replace it with SSH/SFTP; restrict it by firewall.",
            Confidence.FIRM,
            319,
        ),
        FindingRule(
            "network.database_exposed",
            "Database service reachable from the scanned network",
            Severity.HIGH,
            "Database ports exposed to untrusted networks invite brute force and exploitation.",
            "Restrict database ports to application hosts (firewall rules or private networks).",
            Confidence.FIRM,
            668,
        ),
    )
}

# Attention flags emitted by each observation kind → rule id.
FLAG_RULES: Final[Mapping[str, Mapping[str, str]]] = {
    "tls_endpoint": {
        "certificate_expired": "tls.certificate_expired",
        "certificate_expiring_soon": "tls.certificate_expiring_soon",
        "self_signed_certificate": "tls.self_signed_certificate",
        "self_signed_in_chain": "tls.self_signed_in_chain",
        "untrusted_issuer": "tls.untrusted_issuer",
        "hostname_mismatch": "tls.hostname_mismatch",
        "verification_failed": "tls.verification_failed",
        "weak_rsa_key": "tls.weak_rsa_key",
        "weak_signature_algorithm": "tls.weak_signature_algorithm",
        "legacy_protocol_tlsv1_0": "tls.legacy_protocol_tlsv1_0",
        "legacy_protocol_tlsv1_1": "tls.legacy_protocol_tlsv1_1",
    },
    "http_endpoint": {
        "cleartext_http": "http.cleartext_http",
        "missing_hsts": "http.missing_hsts",
        "missing_csp": "http.missing_csp",
        "missing_clickjacking_protection": "http.missing_clickjacking_protection",
        "missing_x_content_type_options": "http.missing_x_content_type_options",
        "missing_referrer_policy": "http.missing_referrer_policy",
        "version_disclosure": "http.version_disclosure",
    },
    "email_security": {
        "spf_missing": "dns.spf_missing",
        "spf_permissive": "dns.spf_permissive",
        "dmarc_missing": "dns.dmarc_missing",
        "dmarc_policy_none": "dns.dmarc_policy_none",
    },
    "caa": {"caa_missing": "dns.caa_missing"},
    "open_port": {
        "cleartext_service": "network.cleartext_service",
        "database_exposed": "network.database_exposed",
    },
}

# Third-party verdict scales → SentinelX scales.
ZAP_RISK: Final = {
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
}
ZAP_CONFIDENCE: Final = {
    "0": Confidence.TENTATIVE,  # false positive (ZAP) — filtered out below
    "1": Confidence.TENTATIVE,
    "2": Confidence.FIRM,
    "3": Confidence.CONFIRMED,
    "4": Confidence.CONFIRMED,  # user-confirmed in ZAP
}
NUCLEI_SEVERITY: Final = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _text(value: object, limit: int = MAX_TEXT) -> str:
    return str(value or "").strip()[:limit]


def _int(value: object) -> int | None:
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _from_rule(rule: FindingRule, key: str, observation: Mapping[str, Any]) -> FindingCandidate:
    return FindingCandidate(
        rule_id=rule.id,
        key=key,
        title=rule.title,
        severity=rule.severity,
        confidence=rule.confidence,
        category=rule.id.split(".", 1)[0],
        description=rule.description,
        remediation=rule.remediation,
        cwe=rule.cwe,
        references=rule.references,
        observation=observation,
    )


def _from_zap(observation: Mapping[str, Any]) -> FindingCandidate | None:
    data: Mapping[str, Any] = observation.get("data") or {}
    confidence_code = str(data.get("confidence_code", "2"))
    if confidence_code == "0":  # ZAP marks the alert as a false positive
        return None
    plugin = _text(data.get("plugin_id"), 20) or "unknown"
    references = tuple(
        r.strip() for r in _text(data.get("reference")).splitlines() if r.strip().startswith("http")
    )[:10]
    return FindingCandidate(
        rule_id=f"zap.{plugin}",
        key=str(observation.get("key", "")),
        title=_text(data.get("name"), 300) or f"ZAP alert {plugin}",
        severity=ZAP_RISK.get(str(data.get("risk_code", "0")), Severity.INFO),
        confidence=ZAP_CONFIDENCE.get(confidence_code, Confidence.TENTATIVE),
        category="web",
        description=_text(data.get("description")),
        remediation=_text(data.get("solution")),
        cwe=_int(data.get("cwe_id")),
        references=references,
        observation=observation,
    )


def _from_nuclei(observation: Mapping[str, Any]) -> FindingCandidate:
    data: Mapping[str, Any] = observation.get("data") or {}
    template = _text(data.get("template_id"), 200) or "unknown"
    cwe_ids = [_int(str(c).upper().removeprefix("CWE-")) for c in data.get("cwe_ids") or []]
    return FindingCandidate(
        rule_id=f"nuclei.{template}",
        key=str(observation.get("key", "")),
        title=_text(data.get("name"), 300) or template,
        severity=NUCLEI_SEVERITY.get(str(data.get("severity", "info")).lower(), Severity.INFO),
        # Template matches are signatures, not proofs of exploitability.
        confidence=Confidence.FIRM,
        category="web",
        description=_text(data.get("description")),
        remediation=_text(data.get("remediation")),
        cwe=next((c for c in cwe_ids if c), None),
        references=tuple(_text(r, 500) for r in (data.get("references") or [])[:10]),
        observation=observation,
    )


def derive_findings(observations: Iterable[Mapping[str, Any]]) -> list[FindingCandidate]:
    """Map observations (as produced by ``Observation.to_dict``) to finding candidates."""
    candidates: dict[tuple[str, str], FindingCandidate] = {}
    for observation in observations:
        kind = str(observation.get("kind", ""))
        key = str(observation.get("key", ""))
        if kind == "web_alert":
            candidate = _from_zap(observation)
            if candidate is not None:
                candidates.setdefault((candidate.rule_id, candidate.key), candidate)
            continue
        if kind == "template_match":
            candidate = _from_nuclei(observation)
            candidates.setdefault((candidate.rule_id, candidate.key), candidate)
            continue
        flag_rules = FLAG_RULES.get(kind, {})
        for flag in observation.get("attention") or ():
            rule_id = flag_rules.get(str(flag))
            if rule_id is not None:
                candidates.setdefault((rule_id, key), _from_rule(RULES[rule_id], key, observation))
    return list(candidates.values())
