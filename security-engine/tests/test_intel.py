"""Threat intelligence: CPE/version logic, NVD parsing, client behaviour, correlation."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from sentinelx_security.findings import Confidence, Severity
from sentinelx_security.intel.correlate import (
    SoftwareComponent,
    correlate,
    extract_components,
    split_version,
)
from sentinelx_security.intel.cpe import Cpe, CpeError, CpeRange, compare_versions
from sentinelx_security.intel.nvd import IntelError, NvdClient, parse_kev, parse_page

FIXTURES = Path(__file__).parent / "fixtures"


def nvd_page() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((FIXTURES / "nvd_page.json").read_text())
    return data


# ----------------------------------------------------------------------------- versions / CPE


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("2.4.49", "2.4.50", -1),
        ("1.10", "1.9", 1),
        ("3.5", "3.5.0", 0),
        ("1.0rc1", "1.0", -1),
        ("1.0.0-beta.2", "1.0.0", -1),
        ("1.0.2k", "1.0.2", 1),
        ("1.0.2k", "1.0.2u", -1),
        ("8.9p1", "8.9", 1),
        ("10.0", "9.99", 1),
        ("2.4.49", "2.4.49", 0),
    ],
)
def test_compare_versions(left: str, right: str, expected: int) -> None:
    assert compare_versions(left, right) == expected
    assert compare_versions(right, left) == -expected


def test_cpe_parsing_handles_escapes() -> None:
    cpe = Cpe.parse("cpe:2.3:a:joomla:joomla\\!:3.9\\:1:*:*:*:*:*:*:*")
    assert (cpe.vendor, cpe.product, cpe.version) == ("joomla", "joomla!", "3.9:1")
    for bad in ("cpe:/a:apache:http_server:2.4", "cpe:2.3:x:a:b:1:*:*:*:*:*:*:*", "nonsense"):
        with pytest.raises(CpeError):
            Cpe.parse(bad)


def test_range_matching_respects_every_bound() -> None:
    jquery = CpeRange.from_criteria(
        "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*", start_including="1.2", end_excluding="3.5.0"
    )
    assert jquery.matches("jquery", "jquery", "1.2")
    assert jquery.matches("jquery", "jquery", "3.4.1")
    assert not jquery.matches("jquery", "jquery", "3.5.0")
    assert not jquery.matches("jquery", "jquery", "1.1.4")
    assert not jquery.matches("jquery", "jquery", "")  # no version → never
    assert not jquery.matches("other", "jquery", "2.0")
    assert jquery.describe() == ">= 1.2 and < 3.5.0"

    exact = CpeRange.from_criteria("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    assert exact.matches("apache", "http_server", "2.4.49")
    assert not exact.matches("apache", "http_server", "2.4.50")

    bounded = CpeRange.from_criteria(
        "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*", start_excluding="1.0", end_including="2.0"
    )
    assert not bounded.matches("x", "y", "1.0")
    assert bounded.matches("x", "y", "2.0")
    assert not bounded.matches("x", "y", "2.0.1")

    not_applicable = CpeRange.from_criteria("cpe:2.3:a:netapp:cloud_backup:-:*:*:*:*:*:*:*")
    assert not not_applicable.matches("netapp", "cloud_backup", "1.0")

    with_update = CpeRange.from_criteria("cpe:2.3:a:openbsd:openssh:7.2:p1:*:*:*:*:*:*")
    assert with_update.matches("openbsd", "openssh", "7.2", "p1")
    assert not with_update.matches("openbsd", "openssh", "7.2", "p2")


# ----------------------------------------------------------------------------- NVD


def test_nvd_page_parsing_from_a_real_response() -> None:
    records, total = parse_page(nvd_page())
    assert total == 2
    apache, jquery = records
    assert apache.id == "CVE-2021-41773"
    assert apache.cvss_v31 is not None
    assert apache.cvss_v31.score == 9.8  # NVD's Primary score, not the CNA's 7.5
    assert apache.cvss_v31.severity == "critical"
    assert apache.cwes == ("CWE-22",)
    assert apache.kev_added == date(2021, 11, 3)
    assert apache.url == "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
    assert all(r.startswith("https://") for r in apache.references)
    assert any(m.product == "http_server" and m.version == "2.4.49" for m in apache.matches)
    assert jquery.id == "CVE-2020-11022"
    (jq,) = [m for m in jquery.matches if m.product == "jquery"]
    assert (jq.start_including, jq.end_excluding) == ("1.2", "3.5.0")


def test_nvd_parsing_is_defensive() -> None:
    records, total = parse_page(
        {
            "totalResults": "lots",
            "vulnerabilities": [
                {"cve": {"id": "CVE-2000-0001", "vulnStatus": "Rejected"}},
                {"cve": {"id": "not-a-cve"}},
                {
                    "cve": {
                        "id": "CVE-2000-0002",
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 99}}]},
                        "configurations": [
                            {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "junk"}]}]}
                        ],
                        "references": [
                            {"url": "javascript:alert(1)"},
                            {"url": "https://ok.example/"},
                        ],
                    }
                },
                "garbage",
            ],
        }
    )
    assert [r.id for r in records] == ["CVE-2000-0002"]
    assert records[0].cvss is None
    assert records[0].matches == ()
    assert records[0].references == ("https://ok.example/",)
    assert total == 1


def test_kev_catalog_parsing() -> None:
    catalog = parse_kev(json.loads((FIXTURES / "kev_sample.json").read_text()))
    assert catalog.version
    entry = catalog.entries["CVE-2021-41773"]
    assert entry.date_added is not None
    assert entry.name


class FakeNvd:
    def __init__(self, pages: list[httpx.Response]) -> None:
        self.pages = pages
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.pages.pop(0)


async def test_client_paginates_sends_key_and_backs_off() -> None:
    page = nvd_page()
    first = {**page, "totalResults": 3, "vulnerabilities": page["vulnerabilities"][:2]}
    second = {**page, "totalResults": 3, "vulnerabilities": page["vulnerabilities"][:1]}
    fake = FakeNvd(
        [httpx.Response(429), httpx.Response(200, json=first), httpx.Response(200, json=second)]
    )
    client = NvdClient(api_key="k", transport=httpx.MockTransport(fake.handler), min_interval=0)
    ids = [r.id async for r in client.by_product("apache", "http_server")]
    assert ids == ["CVE-2021-41773", "CVE-2020-11022", "CVE-2021-41773"]
    assert fake.requests[0].headers["apiKey"] == "k"
    params = fake.requests[-1].url.params
    assert params["virtualMatchString"] == "cpe:2.3:*:apache:http_server"
    assert params["startIndex"] == "2"


async def test_client_splits_long_modification_windows() -> None:
    empty = {"totalResults": 0, "vulnerabilities": []}
    fake = FakeNvd([httpx.Response(200, json=empty) for _ in range(3)])
    client = NvdClient(transport=httpx.MockTransport(fake.handler), min_interval=0)
    start = datetime(2026, 1, 1, tzinfo=UTC)
    _ = [r async for r in client.modified_between(start, start + timedelta(days=300))]
    assert len(fake.requests) == 3
    first = fake.requests[0].url.params
    assert first["lastModStartDate"].startswith("2026-01-01T00:00:00.000")
    assert first["lastModEndDate"].startswith("2026-05-01")


async def test_client_errors_are_typed() -> None:
    fake = FakeNvd([httpx.Response(500)])
    client = NvdClient(transport=httpx.MockTransport(fake.handler), min_interval=0)
    with pytest.raises(IntelError) as info:
        _ = [r async for r in client.by_product("a", "b")]
    assert info.value.code == "source_error"

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    client = NvdClient(transport=httpx.MockTransport(down), min_interval=0, max_retries=1)
    with pytest.raises(IntelError) as info:
        _ = [r async for r in client.by_product("a", "b")]
    assert info.value.code == "source_unavailable"


# ----------------------------------------------------------------------------- correlation


def obs(kind: str, **data: Any) -> dict[str, Any]:
    return {"kind": kind, "key": "k", "data": data, "attention": []}


def test_inventory_extraction() -> None:
    components = extract_components(
        [
            obs("technology", name="Apache", version="2.4.49", url="https://x/"),
            obs("technology", name="jQuery", version=None, url="https://x/"),
            obs(
                "open_port",
                address="1.2.3.4",
                port=22,
                protocol="tcp",
                product="OpenSSH",
                version="8.9p1 Ubuntu 3ubuntu0.1",
            ),
            obs("open_port", address="1.2.3.4", port=80, product=None),
            obs("technology", name="UnknownThing", version="1.0", url="https://x/"),
            obs(
                "template_match",
                matcher_name="nginx",
                tags=["tech"],
                extracted_results=["1.18.0"],
                matched_at="https://x/",
            ),
        ]
    )
    by_name = {c.name: c for c in components}
    assert by_name["Apache"].cpes == (("apache", "http_server"),)
    assert not by_name["jQuery"].correlatable  # no version → never correlated
    ssh = by_name["OpenSSH"]
    assert (ssh.version, ssh.update) == ("8.9", "p1")
    assert ssh.location == "1.2.3.4:22/tcp"
    assert by_name["UnknownThing"].cpes == ()
    assert by_name["nginx"].version == "1.18.0"
    assert split_version("v2.0.1-beta") == ("2.0.1", "beta")
    assert split_version("unknown") == ("", "")


def test_correlation_matches_versions_not_names() -> None:
    records, _ = parse_page(nvd_page())
    components = extract_components(
        [
            obs("technology", name="Apache", version="2.4.49", url="https://a/"),
            obs("technology", name="Apache", version="2.4.58", url="https://b/"),
            obs("technology", name="jQuery", version="3.4.1", url="https://a/"),
            obs("technology", name="jQuery", version="3.5.1", url="https://a/"),
            obs("technology", name="jQuery", url="https://c/"),
        ]
    )
    candidates = correlate(components, records)
    found = {(c.rule_id, c.key) for c in candidates}
    assert found == {
        ("cve.CVE-2021-41773", "apache:http_server:2.4.49 https://a/"),
        ("cve.CVE-2020-11022", "jquery:jquery:3.4.1 https://a/"),
    }
    apache = next(c for c in candidates if c.rule_id == "cve.CVE-2021-41773")
    assert apache.severity is Severity.CRITICAL
    assert apache.confidence is Confidence.TENTATIVE
    assert apache.category == "cve"
    assert apache.cwe == 22
    assert apache.references[0] == "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
    assert "CISA KEV" in apache.description
    assert apache.observation["attention"] == ["kev"]
    assert apache.observation["data"]["range"] == "version 2.4.49"


def test_component_without_cpe_mapping_is_ignored() -> None:
    records, _ = parse_page(nvd_page())
    component = SoftwareComponent("Custom", "2.4.49", "", (), "x", "technology", "2.4.49")
    assert correlate([component], records) == []
