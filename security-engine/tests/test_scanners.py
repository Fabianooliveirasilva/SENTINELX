"""Scanner adapters: parsing, safety invariants and real local execution."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import shutil
import ssl
import uuid
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from sentinelx_security.scanners import (
    CATALOG,
    ScanContext,
    ScanError,
    ScannerName,
    UnsupportedTargetError,
)
from sentinelx_security.scanners.dns import DnsScanner, analyze_dmarc, analyze_spf
from sentinelx_security.scanners.http import HttpScanner, fingerprint, review_headers
from sentinelx_security.scanners.nmap import (
    FORBIDDEN_OPTIONS,
    NmapScanner,
    ProcessResult,
    SubprocessRunner,
    build_argv,
    parse_nmap_xml,
)
from sentinelx_security.scanners.subdomains import SubdomainScanner, extract_subdomains
from sentinelx_security.scanners.tls import TlsScanner
from sentinelx_security.scope import AssetType, ScopeAsset, parse_target
from sentinelx_security.scope.engine import asset_covers

FIXTURES = Path(__file__).parent / "fixtures"


def make_certificate(
    tmp: Path,
    *,
    common_name: str = "lab.example.com",
    days_valid: int = 90,
    expired: bool = False,
    rsa_bits: int | None = None,
) -> tuple[Path, Path]:
    key = (
        rsa.generate_private_key(65537, rsa_bits)
        if rsa_bits
        else ec.generate_private_key(ec.SECP256R1())
    )
    now = datetime.now(UTC)
    start = now - timedelta(days=400 if expired else 1)
    end = now - timedelta(days=1) if expired else now + timedelta(days=days_valid)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(common_name), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp / f"{common_name}.crt", tmp / f"{common_name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@dataclass
class TlsServer:
    port: int


@pytest.fixture
async def tls_server(tmp_path: Path, request: pytest.FixtureRequest) -> AsyncIterator[TlsServer]:
    options = getattr(request, "param", {})
    cert, key = make_certificate(tmp_path, **options)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Lab server only: allow deliberately weak test keys to be served.
    context.set_ciphers("DEFAULT:@SECLEVEL=0")
    context.load_cert_chain(cert, key)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield TlsServer(port=port)


LOOPBACK = ipaddress.ip_address("127.0.0.1")


def ctx(
    target: str, *addresses: str, profile: str = "default", timeout: float = 20.0
) -> ScanContext:
    return ScanContext(
        target=parse_target(target),
        pinned_addresses=tuple(ipaddress.ip_address(a) for a in addresses),
        profile=profile,
        timeout_seconds=timeout,
    )


# ----------------------------------------------------------------------------- nmap


def test_nmap_argv_is_built_from_profiles_and_canonical_ips_only() -> None:
    argv = build_argv("nmap", "web", [ipaddress.ip_address("93.184.215.14")])

    assert argv[:2] == ["nmap", "-sT"]
    assert "--unprivileged" in argv
    assert argv[argv.index("-p") : argv.index("-p") + 2] == [
        "-p",
        "80,443,8000,8008,8080,8443,8888",
    ]
    assert argv[-1] == "93.184.215.14"
    assert not FORBIDDEN_OPTIONS.intersection(argv)
    assert not any(a.startswith("--script") for a in argv)


def test_nmap_ipv6_uses_family_flag_and_rejects_mixed_families() -> None:
    v6 = ipaddress.ip_address("2001:4860::8888")

    assert build_argv("nmap", "quick", [v6])[-2:] == ["-6", "2001:4860::8888"]
    with pytest.raises(ScanError, match="separately"):
        build_argv("nmap", "quick", [v6, ipaddress.ip_address("8.8.8.8")])
    with pytest.raises(ScanError, match="Unknown Nmap profile"):
        build_argv("nmap", "--script=exploit", [v6])
    with pytest.raises(ScanError, match="No authorized"):
        build_argv("nmap", "quick", [])


def test_nmap_xml_parsing_keeps_only_open_ports() -> None:
    parsed = parse_nmap_xml((FIXTURES / "nmap_sample.xml").read_bytes())

    assert parsed["version"] == "7.95"
    ports = parsed["hosts"][0]["ports"]
    assert [p["port"] for p in ports] == [22, 443, 23]
    assert ports[0] == {
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "product": "OpenSSH",
        "version": "9.6p1",
        "extrainfo": "Ubuntu",
        "tunnel": None,
    }


@pytest.mark.parametrize(
    "payload",
    [
        b"not xml at all",
        # Entity expansion ("billion laughs") and external entity (XXE) payloads:
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">'
        b'<!ENTITY b "&a;&a;&a;">]><nmaprun>&b;</nmaprun>',
        b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
        b"<nmaprun>&e;</nmaprun>",
    ],
)
def test_nmap_xml_parsing_rejects_malformed_and_hostile_documents(payload: bytes) -> None:
    with pytest.raises(ScanError) as excinfo:
        parse_nmap_xml(payload)
    assert excinfo.value.code == "invalid_output"


class FakeRunner:
    def __init__(self, stdout: bytes, returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.calls: list[list[str]] = []

    async def run(
        self, argv: Sequence[str], *, timeout_seconds: float, env: Mapping[str, str] | None
    ) -> ProcessResult:
        self.calls.append(list(argv))
        return ProcessResult(self.stdout, b"", self.returncode)


async def test_nmap_scanner_normalizes_observations_and_flags_cleartext() -> None:
    runner = FakeRunner((FIXTURES / "nmap_sample.xml").read_bytes())
    scanner = NmapScanner(runner=runner)

    raw = await scanner.execute(ctx("93.184.215.14", "93.184.215.14", profile="quick"))
    observations = scanner.normalize_results(raw)

    assert runner.calls[0][-1] == "93.184.215.14"
    assert raw.tool_versions == {"nmap": "7.95"}
    telnet = next(o for o in observations if o.key == "93.184.215.14:23/tcp")
    assert telnet.attention == ("cleartext_service",)
    assert scanner.record_evidence(raw)[0].media_type == "application/xml"


async def test_nmap_nonzero_exit_is_a_safe_error() -> None:
    scanner = NmapScanner(runner=FakeRunner(b"", returncode=1))

    with pytest.raises(ScanError, match="exited with an error"):
        await scanner.execute(ctx("93.184.215.14", "93.184.215.14", profile="quick"))


def test_nmap_targets_are_derived_from_host_assets_only() -> None:
    scanner = NmapScanner()
    assert scanner.target_for(AssetType.IP_ADDRESS, "2001:db8::1") == "2001:db8::1"
    assert scanner.target_for(AssetType.DOMAIN, "example.com") == "example.com"
    for asset_type in (AssetType.WEB_APPLICATION, AssetType.API_ENDPOINT, AssetType.SERVICE):
        with pytest.raises(UnsupportedTargetError):
            scanner.target_for(asset_type, "https://app.example.com:8443/x")


async def test_subprocess_runner_kills_on_timeout() -> None:
    sleep = shutil.which("sleep")
    assert sleep
    started = asyncio.get_running_loop().time()

    with pytest.raises(TimeoutError):
        await SubprocessRunner().run([sleep, "10"], timeout_seconds=0.3, env=None)

    assert asyncio.get_running_loop().time() - started < 3


NMAP_BINARY = os.environ.get("SENTINELX_TEST_NMAP_BINARY") or shutil.which("nmap")


@pytest.mark.skipif(not NMAP_BINARY, reason="nmap binary not available")
async def test_real_nmap_discovers_a_local_open_port() -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.close()

    server = None
    for candidate in (8888, 8008, 8000, 8080):  # ports covered by the "web" profile
        try:
            server = await asyncio.start_server(handle, "127.0.0.1", candidate)
            break
        except OSError:
            continue
    if server is None:
        pytest.skip("no free port from the web profile")
    port = server.sockets[0].getsockname()[1]
    # The scope engine never permits loopback; execute() is exercised directly here.
    scanner = NmapScanner(
        binary=str(NMAP_BINARY), datadir=os.environ.get("SENTINELX_TEST_NMAP_DATADIR")
    )
    async with server:
        raw = await scanner.execute(ctx("127.0.0.1", "127.0.0.1", profile="web", timeout=90))

    keys = {o.key for o in scanner.normalize_results(raw)}
    assert f"127.0.0.1:{port}/tcp" in keys
    assert raw.tool_versions["nmap"] != "unknown"


# ----------------------------------------------------------------------------- TLS


async def test_tls_scanner_inspects_self_signed_endpoint(tls_server: TlsServer) -> None:
    scanner = TlsScanner()

    raw = await scanner.execute(ctx(f"127.0.0.1:{tls_server.port}", "127.0.0.1"))
    [observation] = scanner.normalize_results(raw)

    data = observation.data
    assert data["trusted"] is False
    assert data["verification_error"] in {"self_signed_certificate", "untrusted_issuer"}
    assert data["negotiated_protocol"] in {"TLSv1.2", "TLSv1.3"}
    assert data["protocols"]["TLSv1.2"] == "supported"
    assert data["protocols"]["TLSv1.0"] in {"not_supported", "not_testable"}
    assert data["certificate"]["subject_cn"] == "lab.example.com"
    assert data["certificate"]["self_issued"] is True
    assert "pem" not in data["certificate"]
    assert "BEGIN CERTIFICATE" in scanner.record_evidence(raw)[0].content
    assert observation.attention[0] in {"self_signed_certificate", "untrusted_issuer"}


@pytest.mark.parametrize("tls_server", [{"expired": True, "rsa_bits": 1024}], indirect=True)
async def test_tls_scanner_flags_expired_certificate_and_weak_key(tls_server: TlsServer) -> None:
    scanner = TlsScanner()

    raw = await scanner.execute(ctx(f"127.0.0.1:{tls_server.port}", "127.0.0.1"))
    [observation] = scanner.normalize_results(raw)

    assert "certificate_expired" in observation.attention
    assert "weak_rsa_key" in observation.attention
    assert observation.data["certificate"]["days_remaining"] < 0


@pytest.mark.parametrize("tls_server", [{"days_valid": 10}], indirect=True)
async def test_tls_scanner_warns_about_soon_expiring_certificate(tls_server: TlsServer) -> None:
    scanner = TlsScanner()

    raw = await scanner.execute(ctx(f"127.0.0.1:{tls_server.port}", "127.0.0.1"))

    assert "certificate_expiring_soon" in scanner.normalize_results(raw)[0].attention


async def test_tls_connection_refused_is_reported_safely() -> None:
    scanner = TlsScanner()
    server = await asyncio.start_server(lambda _r, _w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()

    with pytest.raises(ConnectionRefusedError) as excinfo:
        await scanner.execute(ctx(f"127.0.0.1:{port}", "127.0.0.1", timeout=5))
    assert scanner.handle_errors(excinfo.value).code == "connection_refused"


def test_tls_target_derivation() -> None:
    scanner = TlsScanner()
    assert scanner.target_for(AssetType.DOMAIN, "example.com") == "example.com:443"
    assert scanner.target_for(AssetType.IP_ADDRESS, "2001:db8::1") == "[2001:db8::1]:443"
    assert scanner.target_for(AssetType.SERVICE, "mail.example.com:465") == "mail.example.com:465"
    assert (
        scanner.target_for(AssetType.WEB_APPLICATION, "https://app.example.com/")
        == "https://app.example.com/"
    )
    with pytest.raises(UnsupportedTargetError):
        scanner.target_for(AssetType.WEB_APPLICATION, "http://app.example.com/")


# ----------------------------------------------------------------------------- DNS


class FakeDns:
    def __init__(self, records: Mapping[str, list[str]]) -> None:
        self.records = records

    async def __call__(self, name: str, rdtype: str) -> list[str]:
        return list(self.records.get(f"{name} {rdtype}", []))


async def test_dns_scanner_collects_records_and_email_posture() -> None:
    scanner = DnsScanner(
        FakeDns(
            {
                "example.com A": ["93.184.215.14"],
                "example.com MX": ["10 mail.example.com."],
                "example.com TXT": [
                    '"v=spf1 include:_spf.example.net ~all"',
                    '"google-site-verification=x"',
                ],
                "_dmarc.example.com TXT": ['"v=DMARC1; p=none; rua=mailto:d@example.com"'],
            }
        )
    )

    raw = await scanner.execute(ctx("example.com"))
    observations = {o.kind + ":" + o.key: o for o in scanner.normalize_results(raw)}

    assert observations["dns_record:example.com A"].data["values"] == ["93.184.215.14"]
    email = observations["email_security:example.com"]
    assert email.data["spf"]["all_qualifier"] == "~"
    assert email.attention == ("dmarc_policy_none",)
    assert observations["caa:example.com"].attention == ("caa_missing",)
    assert "example.com MX 10 mail.example.com." in scanner.record_evidence(raw)[0].content


async def test_dns_scanner_reports_missing_records() -> None:
    scanner = DnsScanner(FakeDns({}))

    observations = scanner.normalize_results(await scanner.execute(ctx("nothing.example.com")))

    assert any(o.attention == ("no_records",) for o in observations)


@pytest.mark.parametrize(
    ("records", "expected"),
    [
        ([], {"present": False, "record": None, "all_qualifier": None}),
        (
            ['"v=spf1 -all"'],
            {"present": True, "record": "v=spf1 -all", "all_qualifier": "-", "multiple": False},
        ),
        (
            ['"v=spf1 +all"', '"v=spf1 ~all"'],
            {"present": True, "record": "v=spf1 +all", "all_qualifier": "+", "multiple": True},
        ),
        (
            ['"v=spf1 a mx"'],
            {"present": True, "record": "v=spf1 a mx", "all_qualifier": None, "multiple": False},
        ),
    ],
)
def test_spf_analysis(records: list[str], expected: dict[str, object]) -> None:
    assert analyze_spf(records) == expected


def test_dmarc_analysis() -> None:
    assert analyze_dmarc(['"v=DMARC1; p=reject"'])["policy"] == "reject"
    assert analyze_dmarc([])["present"] is False


# ----------------------------------------------------------------------------- CT subdomains


def test_ct_extraction_keeps_only_valid_subdomains_with_provenance() -> None:
    entries = json.loads((FIXTURES / "crtsh_sample.json").read_text())

    found = extract_subdomains(entries, "example.com")

    assert sorted(found) == ["api.example.com", "mail.example.com", "www.example.com"]
    assert found["api.example.com"]["first_seen"] == "2025-06-01T00:00:00"
    assert found["api.example.com"]["last_seen"] == "2026-09-01T00:00:00"
    assert found["api.example.com"]["certificates"] == 2
    assert found["www.example.com"]["sources"] == ["crt.sh"]


def _transport(status: int = 200, body: bytes | None = None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["q"] == "%.example.com"
        assert request.url.params["output"] == "json"
        content = body if body is not None else (FIXTURES / "crtsh_sample.json").read_bytes()
        return httpx.Response(status, content=content)

    return httpx.MockTransport(handler)


async def test_subdomain_scanner_queries_ct_and_never_the_target() -> None:
    scanner = SubdomainScanner(base_url="https://ct.test/", transport=_transport())

    raw = await scanner.execute(ctx("example.com"))
    observations = scanner.normalize_results(raw)

    assert [o.key for o in observations] == [
        "api.example.com",
        "mail.example.com",
        "www.example.com",
    ]
    assert all(o.data["parent_domain"] == "example.com" for o in observations)
    assert "unique subdomains: 3" in scanner.record_evidence(raw)[0].content


@pytest.mark.parametrize(
    ("transport", "code"),
    [
        (_transport(status=503), "source_unavailable"),
        (_transport(body=b"{not json"), "invalid_output"),
        (_transport(body=b'{"an": "object"}'), "invalid_output"),
    ],
)
async def test_subdomain_scanner_errors(transport: httpx.MockTransport, code: str) -> None:
    scanner = SubdomainScanner(base_url="https://ct.test/", transport=transport)

    with pytest.raises(ScanError) as excinfo:
        await scanner.execute(ctx("example.com"))
    assert excinfo.value.code == code


async def test_passive_sources_can_be_disabled() -> None:
    with pytest.raises(ScanError, match="disabled"):
        await SubdomainScanner(enabled=False).execute(ctx("example.com"))


def test_catalog_metadata() -> None:
    assert NmapScanner.name is ScannerName.NMAP
    assert set(NmapScanner.profiles) == {"quick", "standard", "web"}
    with pytest.raises(UnsupportedTargetError):
        DnsScanner(FakeDns({})).target_for(AssetType.IP_ADDRESS, "8.8.8.8")


# ----------------------------------------------------------------------------- http

WORDPRESS_PAGE = (
    b"<html><head><title>Lab &amp; shop</title>"
    b'<meta name="generator" content="WordPress 6.4.2">'
    b'<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
    b'<script src="/js/jquery-3.7.1.min.js"></script></head></html>'
)


def _http_transport(seen: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            headers=[
                ("Server", "Apache/2.4.58 (Ubuntu)"),
                ("X-Powered-By", "PHP/8.2.1"),
                ("Set-Cookie", "PHPSESSID=abc; Path=/"),
                ("X-Content-Type-Options", "nosniff"),
            ],
            content=WORDPRESS_PAGE,
        )

    return httpx.MockTransport(handler)


async def test_http_scanner_connects_to_pinned_ip_with_host_header() -> None:
    seen: list[httpx.Request] = []
    scanner = HttpScanner(transport=_http_transport(seen))
    target = scanner.target_for(AssetType.DOMAIN, "shop.example.com")
    assert target == "https://shop.example.com/"
    raw = await scanner.execute(ctx(target, "93.184.215.14"))

    assert [str(r.url) for r in seen] == ["https://93.184.215.14/"]
    assert seen[0].headers["host"] == "shop.example.com"
    assert seen[0].extensions["sni_hostname"] == "shop.example.com"

    observations = scanner.normalize_results(raw)
    endpoint = next(o for o in observations if o.kind == "http_endpoint")
    assert endpoint.data["title"] == "Lab &amp; shop"
    assert endpoint.data["url"] == "https://shop.example.com/"
    assert {"missing_hsts", "missing_csp", "version_disclosure"} <= set(endpoint.attention)
    assert "missing_x_content_type_options" not in endpoint.attention
    techs = {o.data["name"]: o.data for o in observations if o.kind == "technology"}
    assert techs["WordPress"]["version"] == "6.4.2"
    assert techs["Apache"]["version"] == "2.4.58"
    assert techs["PHP"]["version"] == "8.2.1"
    assert {"jQuery"} <= set(techs)
    evidence = scanner.record_evidence(raw)
    assert "server: Apache/2.4.58 (Ubuntu)" in evidence[0].content


async def test_http_scanner_does_not_follow_redirects() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest"})

    scanner = HttpScanner(transport=httpx.MockTransport(handler))
    raw = await scanner.execute(ctx("http://app.example.com:8080/login", "93.184.215.14"))
    assert len(seen) == 1
    assert str(seen[0].url) == "http://93.184.215.14:8080/login"
    assert seen[0].headers["host"] == "app.example.com:8080"
    (endpoint,) = scanner.normalize_results(raw)
    assert endpoint.data["redirect_location"] == "http://169.254.169.254/latest"
    assert "cleartext_http" in endpoint.attention
    assert "missing_hsts" not in endpoint.attention


async def test_http_scanner_bounds_the_body() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"A" * (2 * 1024 * 1024))

    raw = await HttpScanner(transport=httpx.MockTransport(handler)).execute(
        ctx("https://198.51.100.7/", "198.51.100.7")
    )
    assert raw.data["responses"][0]["body_bytes"] == 256 * 1024


@pytest.mark.parametrize(
    ("exc", "code"),
    [
        (httpx.ConnectError("refused"), "connection_failed"),
        (httpx.ReadTimeout("slow"), "timeout"),
        (httpx.RemoteProtocolError("bad"), "http_error"),
    ],
)
async def test_http_scanner_errors_are_safe(exc: Exception, code: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    with pytest.raises(ScanError) as info:
        await HttpScanner(transport=httpx.MockTransport(handler)).execute(
            ctx("https://example.com/", "93.184.215.14")
        )
    assert info.value.code == code


async def test_http_scanner_against_a_local_server() -> None:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\nStrict-Transport-Security: max-age=1\r\n"
            b"Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        raw = await HttpScanner().execute(ctx(f"http://lab.example.com:{port}/", "127.0.0.1"))
    (endpoint, tech) = HttpScanner().normalize_results(raw)
    assert endpoint.data["status_code"] == 200
    assert tech.data["name"] == "nginx"


def test_fingerprint_and_header_review_helpers() -> None:
    techs = fingerprint({"x-generator": "Drupal 10", "cf-ray": "x"}, ["JSESSIONID"], b"")
    assert {t["name"] for t in techs} == {"Cloudflare", "Drupal", "Java Servlet"}
    attention, present = review_headers(
        {"content-security-policy": "frame-ancestors 'none'"}, "https"
    )
    assert "missing_clickjacking_protection" not in attention
    assert present["content-security-policy"] == "frame-ancestors 'none'"


# ----------------------------------------------------------------------------- catalog x scope

SAMPLE_ASSETS = {
    AssetType.DOMAIN: "example.com",
    AssetType.SUBDOMAIN: "api.example.com",
    AssetType.IP_ADDRESS: "93.184.215.14",
    AssetType.WEB_APPLICATION: "https://app.example.com/portal/",
    AssetType.API_ENDPOINT: "http://api.example.com:8080/v1/",
    AssetType.SERVICE: "mail.example.com:587",
}


@pytest.mark.parametrize(
    ("scanner_name", "asset_type"),
    [(name, t) for name, cls in CATALOG.items() for t in sorted(cls.supported_asset_types)],
)
def test_every_derived_target_is_covered_by_its_own_asset(
    scanner_name: ScannerName, asset_type: AssetType
) -> None:
    """A scanner must never be offered for an asset whose derived target would be denied."""
    value = SAMPLE_ASSETS[asset_type]
    try:
        target = CATALOG[scanner_name].target_for(asset_type, value)
    except UnsupportedTargetError:
        return  # rejected up front with a clear message (e.g. TLS on an http:// URL)
    asset = ScopeAsset(id=uuid.uuid4(), type=asset_type, value=value)
    assert asset_covers(asset, parse_target(target), include_subdomains=False), target
