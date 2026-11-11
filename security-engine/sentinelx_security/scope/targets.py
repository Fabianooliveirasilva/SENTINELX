"""Strict parsing and normalization of scan targets.

Targets are user-controlled, so parsing is deliberately conservative: anything
ambiguous is rejected rather than "best-effort" interpreted. In particular:

* Hostnames that a resolver could interpret as an IP address in a non-canonical
  form (``2130706433``, ``0x7f.1``, ``0177.0.0.1``) are rejected; those forms are
  a classic way to smuggle ``127.0.0.1`` past naive filters.
* URLs must be ``http``/``https`` and must not carry credentials.
* IPv6 zone identifiers (``fe80::1%eth0``) are rejected.
* Internationalized names are converted to their IDNA (punycode) form, so a
  homoglyph can never compare equal to an authorized ASCII name.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

import idna

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

MAX_TARGET_LENGTH: Final = 2048
MAX_HOSTNAME_LENGTH: Final = 253
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NUMERIC_LABEL = re.compile(r"^(?:0x[0-9a-f]*|[0-9]+)$")
_DEFAULT_PORTS: Final = {"http": 80, "https": 443}

# Special-use / non-public names (RFC 6761, RFC 6762, RFC 8375, RFC 9476 and
# common private conventions). Only reachable through explicitly configured labs.
SPECIAL_USE_SUFFIXES: Final = (
    "localhost",
    "local",
    "internal",
    "arpa",
    "onion",
    "invalid",
    "test",
    "alt",
    "lan",
    "home",
    "corp",
    "intranet",
)


class TargetError(ValueError):
    """The input is not an acceptable target. ``code`` is machine-readable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class Target:
    """A normalized target. ``host`` is a hostname or the canonical IP text."""

    host: str
    ip: IPAddress | None = None
    scheme: str | None = None
    port: int | None = None
    path: str | None = None

    @property
    def is_ip(self) -> bool:
        return self.ip is not None

    @property
    def is_url(self) -> bool:
        return self.scheme is not None

    @property
    def host_for_netloc(self) -> str:
        return f"[{self.host}]" if isinstance(self.ip, ipaddress.IPv6Address) else self.host

    @property
    def origin(self) -> str:
        if self.scheme is None:
            raise ValueError("target has no scheme")
        port = "" if self.port in (None, _DEFAULT_PORTS[self.scheme]) else f":{self.port}"
        return f"{self.scheme}://{self.host_for_netloc}{port}"

    @property
    def effective_port(self) -> int | None:
        if self.port is not None:
            return self.port
        return _DEFAULT_PORTS.get(self.scheme or "")

    def __str__(self) -> str:
        if self.scheme is not None:
            return f"{self.origin}{self.path or '/'}"
        if self.port is not None:
            return f"{self.host_for_netloc}:{self.port}"
        return self.host


def parse_ip(raw: str) -> IPAddress:
    text = raw.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if "%" in text:
        raise TargetError("invalid_ip", "IPv6 zone identifiers are not allowed.")
    try:
        return ipaddress.ip_address(text)
    except ValueError as exc:
        raise TargetError("invalid_ip", f"{raw!r} is not a valid IP address.") from exc


def _looks_like_ip(text: str) -> bool:
    try:
        parse_ip(text)
    except TargetError:
        return False
    return True


def normalize_hostname(raw: str) -> str:
    host = raw.strip().rstrip(".")
    if not host:
        raise TargetError("invalid_hostname", "Hostname is empty.")
    if "*" in host:
        raise TargetError(
            "invalid_hostname",
            "Wildcards are not allowed; authorize the parent domain with subdomains instead.",
        )
    try:
        host = idna.encode(host, uts46=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise TargetError("invalid_hostname", f"{raw!r} is not a valid hostname.") from exc

    if len(host) > MAX_HOSTNAME_LENGTH:
        raise TargetError("invalid_hostname", "Hostname is too long.")
    labels = host.split(".")
    if any(not _LABEL.fullmatch(label) for label in labels):
        raise TargetError("invalid_hostname", f"{raw!r} is not a valid hostname.")
    if _NUMERIC_LABEL.fullmatch(labels[-1]) or all(_NUMERIC_LABEL.fullmatch(lb) for lb in labels):
        raise TargetError(
            "ambiguous_numeric_host",
            f"{raw!r} could be interpreted as a numeric IP address and is rejected.",
        )
    if len(labels) < 2:
        raise TargetError("invalid_hostname", "Single-label hostnames are not allowed.")
    return host


def is_special_use_hostname(host: str) -> bool:
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in SPECIAL_USE_SUFFIXES)


def is_subdomain_of(host: str, parent: str) -> bool:
    return host.endswith(f".{parent}")


def _parse_host(raw: str) -> tuple[str, IPAddress | None]:
    if _looks_like_ip(raw):
        ip = parse_ip(raw)
        return ip.compressed, ip
    return normalize_hostname(raw), None


def _validate_port(port: int) -> int:
    if not 1 <= port <= 65535:
        raise TargetError("invalid_port", "Port must be between 1 and 65535.")
    return port


def _parse_url(raw: str) -> Target:
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as exc:
        raise TargetError("invalid_url", "The URL is malformed.") from exc
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise TargetError("unsupported_scheme", "Only http and https URLs are supported.")
    if parts.username is not None or parts.password is not None:
        raise TargetError("credentials_in_url", "URLs must not contain credentials.")
    if not parts.hostname:
        raise TargetError("invalid_url", "The URL has no host.")
    host, ip = _parse_host(parts.hostname)
    if port is not None:
        _validate_port(port)
        if port == _DEFAULT_PORTS[scheme]:
            port = None
    path = parts.path or "/"
    return Target(host=host, ip=ip, scheme=scheme, port=port, path=path)


def parse_target(raw: str) -> Target:
    """Parse a hostname, IP address, ``host:port`` or http(s) URL."""
    text = raw.strip()
    if not text:
        raise TargetError("empty_target", "Target is empty.")
    if len(text) > MAX_TARGET_LENGTH:
        raise TargetError("target_too_long", "Target is too long.")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise TargetError("invalid_characters", "Target contains whitespace or control characters.")

    if "://" in text:
        return _parse_url(text)

    if _looks_like_ip(text):
        ip = parse_ip(text)
        return Target(host=ip.compressed, ip=ip)

    # [IPv6]:port or host:port
    match = re.fullmatch(
        r"\[(?P<ip6>[^\]]+)\]:(?P<port>\d{1,5})|(?P<host>[^:\[\]]+):(?P<hport>\d{1,5})", text
    )
    if match:
        port = _validate_port(int(match.group("port") or match.group("hport")))
        if match.group("ip6"):
            ip = parse_ip(match.group("ip6"))
            return Target(host=ip.compressed, ip=ip, port=port)
        host, ip_or_none = _parse_host(match.group("host"))
        return Target(host=host, ip=ip_or_none, port=port)

    if "/" in text or "?" in text or "#" in text or ":" in text:
        raise TargetError("invalid_target", "Use a hostname, IP address, host:port or http(s) URL.")
    return Target(host=normalize_hostname(text))
