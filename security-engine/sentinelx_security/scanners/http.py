"""HTTP technology fingerprinting and security-header review.

Sends a single ``GET`` per pinned address (at most ``MAX_ADDRESSES``) to the
registered URL, or to ``/`` for host assets. Safety properties:

* Connects to the pinned IP, never re-resolving the name; the hostname is sent
  only as the ``Host`` header and TLS SNI (DNS-rebinding defense).
* Redirects are **not** followed. The ``Location`` is recorded so an analyst can
  decide whether the destination is in scope.
* The response body is read up to ``MAX_BODY_BYTES`` and only searched with fixed
  patterns; it is never rendered, executed or stored beyond a bounded excerpt.
* Certificates are not validated here (the TLS scanner reports trust problems);
  this keeps fingerprinting possible on lab hosts with self-signed certificates.
"""

from __future__ import annotations

import re
import ssl
from collections.abc import Mapping
from typing import Any, ClassVar, Final

import httpx

from sentinelx_security.scanners.base import (
    Evidence,
    Observation,
    RawOutput,
    ScanContext,
    ScanError,
    Scanner,
    ScannerName,
)
from sentinelx_security.scope import AssetType, Technique
from sentinelx_security.scope.targets import IPAddress, Target, parse_target

MAX_ADDRESSES: Final = 4
MAX_BODY_BYTES: Final = 256 * 1024
USER_AGENT: Final = "SentinelX/0.4 (+authorized fingerprinting)"

SECURITY_HEADERS: Final[Mapping[str, str]] = {
    "strict-transport-security": "missing_hsts",
    "content-security-policy": "missing_csp",
    "x-content-type-options": "missing_x_content_type_options",
    "referrer-policy": "missing_referrer_policy",
}
DISCLOSURE_HEADERS: Final = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")

COOKIE_HINTS: Final[Mapping[str, str]] = {
    "phpsessid": "PHP",
    "jsessionid": "Java Servlet",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel",
    "connect.sid": "Express",
    "wordpress_logged_in": "WordPress",
    "ci_session": "CodeIgniter",
    "django_language": "Django",
}
HEADER_HINTS: Final[Mapping[str, tuple[str, str]]] = {
    # header → (regex, technology)
    "x-drupal-cache": (r".", "Drupal"),
    "x-generator": (r"(?i)drupal", "Drupal"),
    "x-shopify-stage": (r".", "Shopify"),
    "x-vercel-id": (r".", "Vercel"),
    "cf-ray": (r".", "Cloudflare"),
    "x-amz-cf-id": (r".", "Amazon CloudFront"),
    "x-akamai-transformed": (r".", "Akamai"),
}
BODY_HINTS: Final[tuple[tuple[re.Pattern[bytes], str], ...]] = tuple(
    (re.compile(pattern), name)
    for pattern, name in (
        (rb"/wp-content/|/wp-includes/", "WordPress"),
        (rb"__NEXT_DATA__", "Next.js"),
        (rb"__NUXT__", "Nuxt"),
        (rb"\bng-version=", "Angular"),
        (rb"data-reactroot|react-dom", "React"),
        (rb"drupal-settings-json|/sites/default/files/", "Drupal"),
        (rb"/media/jui/|Joomla!", "Joomla"),
        (rb"cdn\.shopify\.com", "Shopify"),
        (rb"jquery[.-]?(\d[\w.]*)?(\.min)?\.js", "jQuery"),
    )
)
_GENERATOR = re.compile(
    rb"""<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["']([^"'<>]{1,120})["']""",
    re.IGNORECASE,
)
_TITLE = re.compile(rb"<title[^>]*>([^<]{0,300})</title>", re.IGNORECASE)
_VERSION = re.compile(r"\d+\.\d+")


def _unverified_context() -> ssl.SSLContext:
    # Fingerprinting must work on endpoints with invalid certificates; trust is
    # evaluated (and reported) by the TLS scanner instead.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # nosec B501
    return context


def _text(value: bytes) -> str:
    return value.decode("utf-8", "replace").strip()


def fingerprint(
    headers: Mapping[str, str], cookies: list[str], body: bytes
) -> list[dict[str, Any]]:
    """Return detected technologies with the evidence that produced each one."""
    found: dict[str, dict[str, Any]] = {}

    def add(name: str, source: str, version: str | None = None) -> None:
        entry = found.setdefault(name, {"name": name, "version": None, "sources": []})
        if version and not entry["version"]:
            entry["version"] = version
        if source not in entry["sources"]:
            entry["sources"].append(source)

    for header in DISCLOSURE_HEADERS:
        value = headers.get(header)
        if not value:
            continue
        for product in value.split():
            name, _, version = product.partition("/")
            if name and not name.startswith("("):
                add(name[:60], f"header:{header}", version[:40] or None)
    for header, (pattern, name) in HEADER_HINTS.items():
        value = headers.get(header)
        if value is not None and re.search(pattern, value):
            add(name, f"header:{header}")
    for cookie in cookies:
        lowered = cookie.lower()
        for prefix, name in COOKIE_HINTS.items():
            if lowered.startswith(prefix):
                add(name, f"cookie:{cookie[:60]}")
    generator = _GENERATOR.search(body)
    if generator:
        value = _text(generator.group(1))
        product, _, version = value.partition(" ")
        add(product[:60], "html:meta-generator", version[:40] or None)
    for body_pattern, name in BODY_HINTS:
        if body_pattern.search(body):
            add(name, "html:body-pattern")
    return sorted(found.values(), key=lambda t: str(t["name"]).lower())


def review_headers(headers: Mapping[str, str], scheme: str) -> tuple[list[str], dict[str, Any]]:
    """Security-header posture: attention flags plus the observed values."""
    attention: list[str] = []
    present: dict[str, Any] = {}
    for header, flag in SECURITY_HEADERS.items():
        value = headers.get(header)
        present[header] = value[:500] if value else None
        if value is None and (header != "strict-transport-security" or scheme == "https"):
            attention.append(flag)
    frame_options = headers.get("x-frame-options")
    csp = headers.get("content-security-policy") or ""
    present["x-frame-options"] = frame_options[:100] if frame_options else None
    if frame_options is None and "frame-ancestors" not in csp.lower():
        attention.append("missing_clickjacking_protection")
    if any(_VERSION.search(headers.get(h, "")) for h in DISCLOSURE_HEADERS):
        attention.append("version_disclosure")
    if scheme == "http":
        attention.append("cleartext_http")
    return attention, present


class HttpScanner(Scanner):
    name: ClassVar[ScannerName] = ScannerName.HTTP
    technique: ClassVar[Technique] = Technique.ACTIVE
    description: ClassVar[str] = (
        "Technology fingerprinting and security-header review (single GET, no redirects)."
    )
    supported_asset_types = frozenset(
        {
            AssetType.DOMAIN,
            AssetType.SUBDOMAIN,
            AssetType.IP_ADDRESS,
            AssetType.WEB_APPLICATION,
            AssetType.API_ENDPOINT,
        }
    )

    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport

    @classmethod
    def target_for(cls, asset_type: AssetType, value: str) -> str:
        super().target_for(asset_type, value)
        target = parse_target(value)
        if target.is_url:
            return value
        return f"https://{target.host_for_netloc}/"

    @staticmethod
    def _url_for(target: Target, address: IPAddress) -> str:
        scheme = target.scheme or "https"
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed
        port = target.port
        netloc = host if port in (None, 80 if scheme == "http" else 443) else f"{host}:{port}"
        return f"{scheme}://{netloc}{target.path or '/'}"

    async def _fetch(
        self, client: httpx.AsyncClient, target: Target, address: IPAddress
    ) -> dict[str, Any]:
        url = self._url_for(target, address)
        host_header = target.host_for_netloc
        if target.port is not None:
            host_header = f"{host_header}:{target.port}"
        extensions = {} if target.is_ip else {"sni_hostname": target.host}
        async with client.stream(
            "GET", url, headers={"Host": host_header}, extensions=extensions
        ) as response:
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) >= MAX_BODY_BYTES:
                    del body[MAX_BODY_BYTES:]
                    break
            headers = {k.lower(): v for k, v in response.headers.items()}
            cookies = [c.split("=", 1)[0].strip() for c in response.headers.get_list("set-cookie")]
            title = _TITLE.search(body)
            return {
                "address": address.compressed,
                "url": f"{target.origin}{target.path or '/'}",
                "scheme": target.scheme,
                "status_code": response.status_code,
                "http_version": response.http_version,
                "headers": {k: v[:1000] for k, v in list(headers.items())[:100]},
                "cookies": cookies[:50],
                "redirect_location": headers.get("location", "")[:2048] or None,
                "title": _text(title.group(1))[:300] if title else None,
                "body_bytes": len(body),
                "technologies": fingerprint(headers, cookies, bytes(body)),
            }

    async def execute(self, ctx: ScanContext) -> RawOutput:
        if not ctx.target.is_url:
            raise ScanError("unsupported_target", "The HTTP scanner needs a URL target.")
        if not ctx.pinned_addresses:
            raise ScanError("no_addresses", "No authorized addresses to connect to.")
        addresses = ctx.pinned_addresses[:MAX_ADDRESSES]
        per_request = max(3.0, ctx.timeout_seconds / len(addresses))
        responses: list[dict[str, Any]] = []
        async with httpx.AsyncClient(
            transport=self._transport,
            verify=_unverified_context(),
            timeout=per_request,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"},
        ) as client:
            for address in addresses:
                try:
                    responses.append(await self._fetch(client, ctx.target, address))
                except httpx.TimeoutException as exc:
                    raise ScanError(
                        "timeout", "The web server did not respond in time.", retryable=True
                    ) from exc
                except httpx.ConnectError as exc:
                    raise ScanError(
                        "connection_failed", "Could not connect to the web server."
                    ) from exc
                except httpx.HTTPError as exc:
                    raise ScanError(
                        "http_error", "The web server returned an invalid response."
                    ) from exc
        return RawOutput(data={"responses": responses}, tool_versions={"httpx": httpx.__version__})

    def normalize_results(self, raw: RawOutput) -> list[Observation]:
        observations: list[Observation] = []
        for response in raw.data["responses"]:
            attention, security_headers = review_headers(response["headers"], response["scheme"])
            observations.append(
                Observation(
                    kind="http_endpoint",
                    key=f"{response['address']} {response['url']}",
                    data={
                        "address": response["address"],
                        "url": response["url"],
                        "status_code": response["status_code"],
                        "http_version": response["http_version"],
                        "title": response["title"],
                        "redirect_location": response["redirect_location"],
                        "security_headers": security_headers,
                        "cookies": response["cookies"],
                    },
                    attention=tuple(attention),
                )
            )
            observations.extend(
                Observation(
                    kind="technology",
                    key=f"{response['address']} {tech['name']}",
                    data={**tech, "address": response["address"], "url": response["url"]},
                )
                for tech in response["technologies"]
            )
        return observations

    def record_evidence(self, raw: RawOutput) -> list[Evidence]:
        return [
            Evidence.bounded(
                f"Response headers from {r['address']} ({r['status_code']})",
                f"GET {r['url']}\n"
                f"{r['http_version']} {r['status_code']}\n"
                + "\n".join(f"{k}: {v}" for k, v in r["headers"].items()),
            )
            for r in raw.data["responses"]
        ]
