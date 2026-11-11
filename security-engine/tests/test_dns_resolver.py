"""DnsResolver behaviour with dnspython's resolver replaced by a stub."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import dns.exception
import dns.resolver
import pytest

from sentinelx_security.scope import DnsResolver, ResolutionError


class _Record:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


def _stub(behaviour: Callable[[str], list[str]]) -> Callable[..., Any]:
    async def resolve(hostname: str, rdtype: str, **_: Any) -> list[_Record]:
        return [_Record(t) for t in behaviour(rdtype)]

    return resolve


def _resolver(
    monkeypatch: pytest.MonkeyPatch, behaviour: Callable[[str], list[str]]
) -> DnsResolver:
    resolver = DnsResolver(timeout_seconds=1.0, nameservers=["9.9.9.9"])
    monkeypatch.setattr(resolver._resolver, "resolve", _stub(behaviour))
    return resolver


async def test_merges_and_sorts_a_and_aaaa(monkeypatch: pytest.MonkeyPatch) -> None:
    def records(rdtype: str) -> list[str]:
        return ["2001:4860::1"] if rdtype == "AAAA" else ["8.8.8.8", "8.8.4.4", "8.8.8.8"]

    addresses = await _resolver(monkeypatch, records).resolve("dns.example.com")

    assert [a.compressed for a in addresses] == ["8.8.4.4", "8.8.8.8", "2001:4860::1"]


async def test_missing_record_types_are_tolerated(monkeypatch: pytest.MonkeyPatch) -> None:
    def records(rdtype: str) -> list[str]:
        if rdtype == "AAAA":
            raise dns.resolver.NoAnswer
        return ["93.184.215.14"]

    assert len(await _resolver(monkeypatch, records).resolve("example.com")) == 1


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (dns.resolver.NXDOMAIN, "dns_no_records"),
        (dns.exception.Timeout, "dns_timeout"),
        (dns.resolver.NoNameservers, "dns_error"),
    ],
)
async def test_failures_map_to_resolution_errors(
    monkeypatch: pytest.MonkeyPatch, error: type[Exception], code: str
) -> None:
    def records(rdtype: str) -> list[str]:
        raise error

    with pytest.raises(ResolutionError) as excinfo:
        await _resolver(monkeypatch, records).resolve("example.com")
    assert excinfo.value.code == code
