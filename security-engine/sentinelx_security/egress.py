"""Scope-enforcing egress proxy for third-party scanners (ZAP, Nuclei).

Tools such as ZAP and Nuclei resolve hostnames themselves, which would bypass the
addresses pinned by the scope engine (DNS rebinding) and could follow links to
any host. They are therefore configured to send **all** traffic through this
proxy, which:

* accepts only ``CONNECT host:port`` (HTTPS tunnels, no TLS interception) and
  absolute-form HTTP requests (``GET http://host:port/path``);
* allows a request only when ``(host, port)`` is in the policy built from the
  execution-time scope decision;
* connects to the **pinned IP addresses** of that host — the proxy never resolves
  DNS — so a name cannot be re-pointed at an internal address mid-scan;
* enforces a connection and byte budget and an idle timeout;
* records every denied destination for the scan's evidence.

The ZAP container has no network route except to this proxy, so the policy is
enforced by the network, not only by tool configuration.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

from sentinelx_security.scope.targets import (
    IPAddress,
    Target,
    TargetError,
    normalize_hostname,
    parse_ip,
)

MAX_HEADER_BYTES: Final = 16 * 1024
IDLE_TIMEOUT_SECONDS: Final = 30.0
CONNECT_TIMEOUT_SECONDS: Final = 10.0
MAX_DENIALS_RECORDED: Final = 100
_HOP_BY_HOP: Final = frozenset(
    {
        b"proxy-connection",
        b"proxy-authorization",
        b"connection",
        b"keep-alive",
        b"te",
        b"trailer",
        b"upgrade",
    }
)


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    """Allowed ``(host, port)`` destinations and the pinned addresses for each."""

    destinations: Mapping[tuple[str, int], tuple[IPAddress, ...]]
    max_connections: int = 5000
    max_bytes: int = 512 * 1024 * 1024

    @classmethod
    def for_target(
        cls, target: Target, addresses: tuple[IPAddress, ...], **limits: int
    ) -> EgressPolicy:
        port = target.effective_port
        if port is None:
            raise ValueError("an egress policy needs a URL or host:port target")
        destinations: dict[tuple[str, int], tuple[IPAddress, ...]] = {
            (target.host, port): addresses
        }
        # Tools sometimes address the pinned IP literal directly.
        for address in addresses:
            destinations[(address.compressed, port)] = (address,)
        return cls(destinations=destinations, **limits)

    def resolve(self, host: str, port: int) -> tuple[IPAddress, ...] | None:
        try:
            canonical = parse_ip(host.strip("[]")).compressed
        except TargetError:
            try:
                canonical = normalize_hostname(host)
            except TargetError:
                return None
        return self.destinations.get((canonical, port))


@dataclass(slots=True)
class EgressStats:
    connections: int = 0
    bytes_transferred: int = 0
    denied: list[str] = field(default_factory=list)
    denied_total: int = 0

    def deny(self, destination: str) -> None:
        self.denied_total += 1
        if len(self.denied) < MAX_DENIALS_RECORDED:
            self.denied.append(destination)

    def summary(self) -> dict[str, object]:
        return {
            "connections": self.connections,
            "bytes_transferred": self.bytes_transferred,
            "denied_total": self.denied_total,
            "denied_destinations": sorted(set(self.denied)),
        }


def _split_host_port(authority: str, default_port: int) -> tuple[str, int] | None:
    authority = authority.strip()
    if authority.startswith("["):
        host, _, rest = authority[1:].partition("]")
        port_text = rest.removeprefix(":")
    elif authority.count(":") == 1:
        host, _, port_text = authority.partition(":")
    else:
        host, port_text = authority, ""
    if not host:
        return None
    if not port_text:
        return host, default_port
    if not port_text.isdigit() or not 0 < int(port_text) < 65536:
        return None
    return host, int(port_text)


class EgressGuard:
    """An asyncio forward proxy enforcing an :class:`EgressPolicy`."""

    def __init__(self, policy: EgressPolicy) -> None:
        self.policy = policy
        self.stats = EgressStats()
        self._server: asyncio.Server | None = None

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> tuple[str, int]:
        self._server = await asyncio.start_server(self._handle, host, port)
        bound = self._server.sockets[0].getsockname()
        return str(bound[0]), int(bound[1])

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    async def __aenter__(self) -> EgressGuard:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    # ------------------------------------------------------------------ protocol

    async def _reply(self, writer: asyncio.StreamWriter, status: str, body: str = "") -> None:
        payload = body.encode()
        writer.write(
            f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {len(payload)}\r\n"
            "X-SentinelX-Egress: denied\r\nConnection: close\r\n\r\n".encode()
            + payload
        )
        with contextlib.suppress(ConnectionError):
            await writer.drain()

    async def _open_upstream(
        self, addresses: tuple[IPAddress, ...], port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        for address in addresses:
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(address.compressed, port),
                    timeout=CONNECT_TIMEOUT_SECONDS,
                )
            except (OSError, TimeoutError):
                continue
        return None

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT_SECONDS)
                if not chunk:
                    break
                self.stats.bytes_transferred += len(chunk)
                if self.stats.bytes_transferred > self.policy.max_bytes:
                    break
                writer.write(chunk)
                await writer.drain()
        except (OSError, TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            try:
                head = await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), timeout=IDLE_TIMEOUT_SECONDS
                )
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
                return
            if len(head) > MAX_HEADER_BYTES:
                await self._reply(writer, "431 Request Header Fields Too Large")
                return
            request_line, *header_lines = head[:-4].split(b"\r\n")
            parts = request_line.decode("latin-1").split(" ")
            if len(parts) != 3:
                await self._reply(writer, "400 Bad Request")
                return
            method, uri, version = parts

            if method.upper() == "CONNECT":
                parsed = _split_host_port(uri, 443)
                path = ""
            elif uri.lower().startswith("http://"):
                authority, slash, rest = uri[7:].partition("/")
                parsed = _split_host_port(authority, 80)
                path = slash + rest or "/"
            else:
                await self._reply(writer, "400 Bad Request", "Only proxy requests are accepted.")
                return
            if parsed is None:
                await self._reply(writer, "400 Bad Request")
                return
            host, port = parsed
            destination = f"{host}:{port}"
            addresses = self.policy.resolve(host, port)
            if not addresses:
                self.stats.deny(destination)
                await self._reply(writer, "403 Forbidden", "Destination is out of scope.")
                return
            if self.stats.connections >= self.policy.max_connections:
                self.stats.deny(f"{destination} (budget)")
                await self._reply(writer, "429 Too Many Requests", "Connection budget exhausted.")
                return
            self.stats.connections += 1
            upstream = await self._open_upstream(addresses, port)
            if upstream is None:
                await self._reply(writer, "502 Bad Gateway")
                return
            upstream_reader, upstream_writer = upstream

            if method.upper() == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
            else:
                headers = [
                    line
                    for line in header_lines
                    if line.split(b":", 1)[0].strip().lower() not in _HOP_BY_HOP
                ]
                headers.append(b"Connection: close")
                upstream_writer.write(
                    f"{method} {path} {version}\r\n".encode("latin-1")
                    + b"\r\n".join(headers)
                    + b"\r\n\r\n"
                )
                await upstream_writer.drain()
            await asyncio.gather(
                self._pipe(reader, upstream_writer), self._pipe(upstream_reader, writer)
            )
        except (OSError, UnicodeDecodeError):
            pass
        finally:
            for w in (writer, upstream_writer):
                if w is not None:
                    with contextlib.suppress(Exception):
                        w.close()
