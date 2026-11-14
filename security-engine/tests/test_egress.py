"""Egress guard: only the authorized destination, only pinned addresses, never DNS."""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import AsyncIterator
from dataclasses import dataclass

import httpx
import pytest

from sentinelx_security.egress import EgressGuard, EgressPolicy
from sentinelx_security.scope import parse_target

LOOPBACK = ipaddress.ip_address("127.0.0.1")
# Not resolvable anywhere: success proves the guard connected to the pinned IP.
LAB_HOST = "lab.sentinelx-tests.invalid"


@dataclass
class Upstream:
    port: int
    requests: list[bytes]


@pytest.fixture
async def upstream() -> AsyncIterator[Upstream]:
    """HTTP server on loopback; also echoes raw bytes for tunnel tests."""
    requests: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        requests.append(head)
        if head.startswith(b"PING"):
            writer.write(b"PONG")
        else:
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    async with server:
        yield Upstream(port=server.sockets[0].getsockname()[1], requests=requests)


def _policy(port: int, **limits: int) -> EgressPolicy:
    return EgressPolicy.for_target(
        parse_target(f"http://{LAB_HOST}:{port}/"), (LOOPBACK,), **limits
    )


async def _client(guard: EgressGuard) -> httpx.AsyncClient:
    host, port = await guard.start()
    return httpx.AsyncClient(proxy=f"http://{host}:{port}", trust_env=False, timeout=5)


async def test_allowed_host_is_reached_via_pinned_address(upstream: Upstream) -> None:
    async with EgressGuard(_policy(upstream.port)) as guard, await _client(guard) as client:
        response = await client.get(
            f"http://{LAB_HOST}:{upstream.port}/a?b=1",
            headers={"Proxy-Authorization": "secret"},
        )
    assert response.status_code == 200
    assert response.text == "hello"
    head = upstream.requests[0].decode()
    assert head.startswith("GET /a?b=1 HTTP/1.1\r\n")  # origin-form upstream
    assert f"Host: {LAB_HOST}:{upstream.port}" in head
    assert "Proxy-Authorization" not in head
    assert guard.stats.connections == 1
    assert guard.stats.denied_total == 0


@pytest.mark.parametrize(
    "url", ["http://evil.example.com/", "http://169.254.169.254/latest/meta-data/"]
)
async def test_other_destinations_are_denied(upstream: Upstream, url: str) -> None:
    async with EgressGuard(_policy(upstream.port)) as guard, await _client(guard) as client:
        response = await client.get(url)
    assert response.status_code == 403
    assert response.headers["x-sentinelx-egress"] == "denied"
    assert guard.stats.denied
    assert upstream.requests == []


async def test_pinned_ip_literal_on_the_authorized_port_is_allowed(upstream: Upstream) -> None:
    async with EgressGuard(_policy(upstream.port)) as guard, await _client(guard) as client:
        response = await client.get(f"http://127.0.0.1:{upstream.port}/")
    assert response.status_code == 200


async def test_wrong_port_on_allowed_host_is_denied(upstream: Upstream) -> None:
    async with EgressGuard(_policy(upstream.port)) as guard, await _client(guard) as client:
        response = await client.get(f"http://{LAB_HOST}:{upstream.port + 1}/")
    assert response.status_code == 403
    assert guard.stats.summary()["denied_destinations"] == [f"{LAB_HOST}:{upstream.port + 1}"]


async def _connect(
    proxy_port: int, authority: str
) -> tuple[bytes, asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
    await writer.drain()
    status = await reader.readuntil(b"\r\n\r\n")
    return status, reader, writer


async def test_connect_tunnels_to_pinned_address_only(upstream: Upstream) -> None:
    async with EgressGuard(_policy(upstream.port)) as guard:
        _, proxy_port = await guard.start()
        status, reader, writer = await _connect(proxy_port, f"{LAB_HOST}:{upstream.port}")
        assert status.startswith(b"HTTP/1.1 200")
        writer.write(b"PING\r\n\r\n")
        await writer.drain()
        assert await reader.read(4) == b"PONG"
        writer.close()

        status, _, writer = await _connect(proxy_port, "internal.example.com:443")
        assert status.startswith(b"HTTP/1.1 403")
        writer.close()


async def test_connection_budget(upstream: Upstream) -> None:
    guard = EgressGuard(_policy(upstream.port, max_connections=1))
    async with guard, await _client(guard) as client:
        assert (await client.get(f"http://{LAB_HOST}:{upstream.port}/")).status_code == 200
        assert (await client.get(f"http://{LAB_HOST}:{upstream.port}/")).status_code == 429


async def test_non_proxy_requests_are_rejected() -> None:
    async with EgressGuard(_policy(8080)) as guard:
        _, port = await guard.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        await writer.drain()
        assert (await reader.readuntil(b"\r\n")).startswith(b"HTTP/1.1 400")
        writer.close()


def test_policy_canonicalizes_hosts() -> None:
    policy = EgressPolicy.for_target(parse_target("https://Lab.Example.COM/"), (LOOPBACK,))
    assert policy.resolve("LAB.example.com.", 443) == (LOOPBACK,)
    assert policy.resolve("127.0.0.1", 443) == (LOOPBACK,)
    assert policy.resolve("lab.example.com", 80) is None
    assert policy.resolve("bad host", 443) is None
