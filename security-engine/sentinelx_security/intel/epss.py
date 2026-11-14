"""FIRST EPSS client (exploit prediction scores), batched and defensive."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any, Final

import httpx

from sentinelx_security.intel.nvd import USER_AGENT, IntelError

EPSS_URL: Final = "https://api.first.org/data/v1/epss"
BATCH: Final = 100
_CVE: Final = re.compile(r"^CVE-\d{4}-\d{4,7}$")


@dataclass(frozen=True, slots=True)
class EpssScore:
    cve_id: str
    probability: float
    percentile: float
    scored_on: date | None


def parse_epss(payload: Mapping[str, Any]) -> dict[str, EpssScore]:
    scores: dict[str, EpssScore] = {}
    data = payload.get("data")
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cve", ""))
        try:
            probability = float(item.get("epss", ""))
            percentile = float(item.get("percentile", ""))
        except (TypeError, ValueError):
            continue
        if not _CVE.match(cve) or not (0 <= probability <= 1 and 0 <= percentile <= 1):
            continue
        try:
            scored = date.fromisoformat(str(item.get("date", ""))[:10])
        except ValueError:
            scored = None
        scores[cve] = EpssScore(cve, probability, percentile, scored)
    return scores


async def fetch_epss(
    cve_ids: Iterable[str],
    *,
    url: str = EPSS_URL,
    transport: httpx.AsyncBaseTransport | None = None,
    min_interval: float = 1.0,
) -> dict[str, EpssScore]:
    ids = sorted({c for c in cve_ids if _CVE.match(c)})
    results: dict[str, EpssScore] = {}
    async with httpx.AsyncClient(
        transport=transport, timeout=30, headers={"User-Agent": USER_AGENT}, trust_env=False
    ) as client:
        for start in range(0, len(ids), BATCH):
            if start:
                await asyncio.sleep(min_interval)
            try:
                response = await client.get(
                    url, params={"cve": ",".join(ids[start : start + BATCH])}
                )
            except httpx.HTTPError as exc:
                raise IntelError("source_unavailable", "The EPSS source is unreachable.") from exc
            if response.status_code != httpx.codes.OK:
                raise IntelError(
                    "source_error", f"The EPSS source returned {response.status_code}."
                )
            payload = response.json()
            results.update(parse_epss(payload if isinstance(payload, dict) else {}))
    return results
