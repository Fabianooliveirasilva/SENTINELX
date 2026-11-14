"""Software inventory from observations, and CVE correlation.

Inventory: technology fingerprints (HTTP scanner), service banners (Nmap
``-sV``) and Nuclei technology matches name products. A curated table maps those
names to NVD CPE ``vendor:product`` pairs; unknown names are kept in the
inventory but never correlated. **A component without a version is never
correlated** — product-name-only matches are not evidence.

Correlation: a CVE applies when one of its *vulnerable* CPE ranges matches the
component's vendor, product and version. The resulting findings are
``tentative``: banners can be wrong or spoofed and distributions backport fixes
without changing the upstream version string, so an analyst must confirm.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from sentinelx_security.findings import Confidence, FindingCandidate, Severity
from sentinelx_security.intel.nvd import CveRecord

# Lower-cased product names as reported by scanners → candidate NVD vendor:product
# pairs (NVD sometimes changed the vendor over time; all candidates are queried).
PRODUCT_CPES: Final[Mapping[str, tuple[tuple[str, str], ...]]] = {
    "apache": (("apache", "http_server"),),
    "apache httpd": (("apache", "http_server"),),
    "apache http server": (("apache", "http_server"),),
    "nginx": (("f5", "nginx"), ("nginx", "nginx")),
    "openresty": (("openresty", "openresty"),),
    "lighttpd": (("lighttpd", "lighttpd"),),
    "microsoft-iis": (("microsoft", "internet_information_services"),),
    "microsoft iis httpd": (("microsoft", "internet_information_services"),),
    "apache tomcat": (("apache", "tomcat"),),
    "apache-coyote": (("apache", "tomcat"),),
    "php": (("php", "php"),),
    "openssl": (("openssl", "openssl"),),
    "openssh": (("openbsd", "openssh"),),
    "wordpress": (("wordpress", "wordpress"),),
    "drupal": (("drupal", "drupal"),),
    "joomla": (("joomla", "joomla\\!"),),
    "jquery": (("jquery", "jquery"),),
    "express": (("expressjs", "express"), ("openjsf", "express")),
    "node.js": (("nodejs", "node.js"),),
    "vsftpd": (("vsftpd_project", "vsftpd"), ("beasts", "vsftpd")),
    "proftpd": (("proftpd", "proftpd"),),
    "exim": (("exim", "exim"),),
    "exim smtpd": (("exim", "exim"),),
    "postfix smtpd": (("postfix", "postfix"),),
    "dovecot": (("dovecot", "dovecot"),),
    "dovecot imapd": (("dovecot", "dovecot"),),
    "mysql": (("oracle", "mysql"), ("mysql", "mysql")),
    "mariadb": (("mariadb", "mariadb"),),
    "postgresql": (("postgresql", "postgresql"),),
    "redis": (("redis", "redis"),),
    "redis key-value store": (("redis", "redis"),),
    "mongodb": (("mongodb", "mongodb"),),
    "grafana": (("grafana", "grafana"),),
    "jenkins": (("jenkins", "jenkins"),),
    "gitlab": (("gitlab", "gitlab"),),
    "microsoft exchange": (("microsoft", "exchange_server"),),
    "bind": (("isc", "bind"),),
    "isc bind": (("isc", "bind"),),
}
_VERSION: Final = re.compile(r"^v?(\d+(?:\.\d+){0,4})(?:[._-]?([a-z]+\d*))?", re.IGNORECASE)
_SEVERITY_FROM_SCORE: Final = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
)


@dataclass(frozen=True, slots=True)
class SoftwareComponent:
    name: str
    version: str
    update: str
    cpes: tuple[tuple[str, str], ...]
    location: str
    source_kind: str
    raw_version: str

    @property
    def correlatable(self) -> bool:
        return bool(self.version and self.cpes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "update": self.update,
            "cpes": [f"{v}:{p}" for v, p in self.cpes],
            "location": self.location,
            "source_kind": self.source_kind,
            "raw_version": self.raw_version,
        }


def split_version(raw: str) -> tuple[str, str]:
    """``"8.9p1 Ubuntu-3"`` → ``("8.9", "p1")``; ``""`` when no version is present."""
    match = _VERSION.match(raw.strip())
    if not match:
        return "", ""
    return match.group(1), (match.group(2) or "").lower()


def _component(name: object, version: object, location: str, kind: str) -> SoftwareComponent | None:
    if not isinstance(name, str) or not name.strip():
        return None
    clean = " ".join(name.split())[:100]
    raw = version.strip()[:60] if isinstance(version, str) else ""
    base, update = split_version(raw)
    return SoftwareComponent(
        name=clean,
        version=base,
        update=update,
        cpes=PRODUCT_CPES.get(clean.lower(), ()),
        location=location[:300],
        source_kind=kind,
        raw_version=raw,
    )


def extract_components(observations: Iterable[Mapping[str, Any]]) -> list[SoftwareComponent]:
    found: dict[tuple[str, str, str], SoftwareComponent] = {}
    for observation in observations:
        kind = str(observation.get("kind", ""))
        data = observation.get("data")
        if not isinstance(data, Mapping):
            continue
        component: SoftwareComponent | None = None
        if kind == "technology":
            component = _component(
                data.get("name"), data.get("version"), str(data.get("url") or ""), kind
            )
        elif kind == "open_port":
            location = f"{data.get('address')}:{data.get('port')}/{data.get('protocol', 'tcp')}"
            component = _component(data.get("product"), data.get("version"), location, kind)
        elif kind == "template_match" and "tech" in (data.get("tags") or []):
            extracted = data.get("extracted_results") or []
            component = _component(
                data.get("matcher_name") or data.get("name"),
                extracted[0] if extracted else None,
                str(data.get("matched_at") or ""),
                kind,
            )
        if component is not None:
            found.setdefault(
                (component.name.lower(), component.version, component.location), component
            )
    return list(found.values())


def severity_from(record: CveRecord) -> Severity:
    score = record.cvss
    if score is None:
        return Severity.MEDIUM  # unscored CVEs are not assumed harmless
    for threshold, severity in _SEVERITY_FROM_SCORE:
        if score.score >= threshold:
            return severity
    return Severity.INFO


def correlate(
    components: Iterable[SoftwareComponent], records: Iterable[CveRecord]
) -> list[FindingCandidate]:
    """Match components against CVE records; one candidate per (CVE, component)."""
    index: dict[tuple[str, str], list[CveRecord]] = {}
    for record in records:
        for cpe_range in record.matches:
            bucket = index.setdefault((cpe_range.vendor, cpe_range.product), [])
            if not bucket or bucket[-1] is not record:
                bucket.append(record)

    candidates: dict[tuple[str, str], FindingCandidate] = {}
    for component in components:
        if not component.correlatable:
            continue
        for vendor, product in component.cpes:
            for record in index.get((vendor, product), []):
                matched = next(
                    (
                        r
                        for r in record.matches
                        if r.matches(vendor, product, component.version, component.update)
                    ),
                    None,
                )
                if matched is None:
                    continue
                shown = component.raw_version or component.version
                key = f"{vendor}:{product}:{shown} {component.location}"
                if (record.id, key) in candidates:
                    continue
                score = record.cvss
                cwe = next(
                    (int(c.removeprefix("CWE-")) for c in record.cwes if c[4:].isdigit()), None
                )
                kev = f" Listed in CISA KEV since {record.kev_added}." if record.kev_added else ""
                candidates[(record.id, key)] = FindingCandidate(
                    rule_id=f"cve.{record.id}",
                    key=key,
                    title=f"{record.id} in {component.name} {shown}",
                    severity=severity_from(record),
                    confidence=Confidence.TENTATIVE,
                    category="cve",
                    description=(
                        f"{record.description}\n\nMatched because {component.name} reports version "
                        f"{component.raw_version or component.version} ({component.source_kind} at "
                        f"{component.location}), inside the NVD range {matched.describe()} for "
                        f"{vendor}:{product}.{kev} Version-based matches are tentative: the banner "
                        "may be inaccurate and distributions often backport fixes without "
                        "changing the version."
                    ),
                    remediation=(
                        f"Confirm the installed {component.name} build and its vendor advisories; "
                        f"upgrade outside {matched.describe()} or apply the vendor fix."
                    ),
                    cwe=cwe,
                    references=(record.url, *record.references[:9]),
                    observation={
                        "kind": "cve_match",
                        "key": key,
                        "data": {
                            "cve_id": record.id,
                            "component": component.to_dict(),
                            "cpe": matched.criteria,
                            "range": matched.describe(),
                            "cvss": (
                                {
                                    "version": score.version,
                                    "vector": score.vector,
                                    "score": score.score,
                                }
                                if score
                                else None
                            ),
                            "kev_added": record.kev_added.isoformat() if record.kev_added else None,
                        },
                        "attention": ["kev"] if record.kev_added else [],
                    },
                )
    return list(candidates.values())
