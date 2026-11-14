"""NVD CVE API 2.0 client and parser, plus the CISA KEV catalog.

* Rate limits follow NVD guidance: at most 5 requests per rolling 30 s without an
  API key (one request every 6 s) and 50 with a key; a delay is always inserted
  between requests and 403/429/503 responses back off and retry a bounded number
  of times.
* Responses are untrusted: sizes are capped, every field is type-checked and
  truncated, rejected CVEs are skipped, and unknown CPE strings are ignored.
* Provenance (source, NVD ``lastModified``, fetch time) is kept with every record.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any, Final

import httpx

from sentinelx_security.intel.cpe import CpeError, CpeRange

NVD_URL: Final = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL: Final = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
MAX_RESPONSE_BYTES: Final = 64 * 1024 * 1024
RESULTS_PER_PAGE: Final = 2000
MAX_WINDOW: Final = timedelta(days=120)  # NVD limit for lastMod ranges
MAX_PAGES: Final = 200
USER_AGENT: Final = "SentinelX/0.6 (+threat-intelligence sync)"


class IntelError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class CvssScore:
    version: str
    vector: str
    score: float
    severity: str


@dataclass(frozen=True, slots=True)
class CveRecord:
    id: str
    description: str
    published: datetime | None
    last_modified: datetime | None
    status: str
    cvss_v31: CvssScore | None
    cvss_v40: CvssScore | None
    cwes: tuple[str, ...]
    references: tuple[str, ...]
    matches: tuple[CpeRange, ...]
    kev_added: date | None = None
    source: str = "nvd"

    @property
    def cvss(self) -> CvssScore | None:
        """Preferred score: CVSS v4.0 when NVD provides it, else v3.1."""
        return self.cvss_v40 or self.cvss_v31

    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.id}"


@dataclass(frozen=True, slots=True)
class KevEntry:
    cve_id: str
    date_added: date | None
    due_date: date | None
    ransomware: str
    name: str


@dataclass(slots=True)
class KevCatalog:
    version: str
    entries: dict[str, KevEntry] = field(default_factory=dict)


def _text(value: object, limit: int) -> str:
    return value[:limit] if isinstance(value, str) else ""


def _datetime(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _date(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, dict) else {}


def _score(metrics: Mapping[str, Any], key: str) -> CvssScore | None:
    entries = [_mapping(m) for m in _list(metrics.get(key))]
    # Prefer NVD's own ("Primary") assessment over secondary (CNA) scores.
    entries.sort(key=lambda m: m.get("type") != "Primary")
    for entry in entries:
        data = _mapping(entry.get("cvssData"))
        score = data.get("baseScore")
        if isinstance(score, int | float) and 0 <= score <= 10:
            return CvssScore(
                version=_text(data.get("version"), 8),
                vector=_text(data.get("vectorString"), 200),
                score=float(score),
                severity=_text(data.get("baseSeverity") or entry.get("baseSeverity"), 16).lower(),
            )
    return None


def _matches(configurations: object) -> tuple[CpeRange, ...]:
    ranges: dict[str, CpeRange] = {}
    for configuration in _list(configurations):
        for node in _list(_mapping(configuration).get("nodes")):
            for match in _list(_mapping(node).get("cpeMatch")):
                match = _mapping(match)
                if match.get("vulnerable") is not True:
                    continue  # platform/context entries (e.g. "running on" an OS)
                criteria = _text(match.get("criteria"), 500)
                bounds = {
                    "start_including": _text(match.get("versionStartIncluding"), 64) or None,
                    "start_excluding": _text(match.get("versionStartExcluding"), 64) or None,
                    "end_including": _text(match.get("versionEndIncluding"), 64) or None,
                    "end_excluding": _text(match.get("versionEndExcluding"), 64) or None,
                }
                try:
                    cpe_range = CpeRange.from_criteria(criteria, **bounds)
                except CpeError:
                    continue
                ranges[f"{criteria}|{sorted(bounds.items())}"] = cpe_range
    return tuple(ranges.values())


def parse_cve(raw: Mapping[str, Any]) -> CveRecord | None:
    cve = _mapping(raw.get("cve"))
    cve_id = _text(cve.get("id"), 32)
    if not cve_id.startswith("CVE-"):
        return None
    status = _text(cve.get("vulnStatus"), 32)
    if status.lower() == "rejected":
        return None
    description = next(
        (
            _text(d.get("value"), 8000)
            for d in map(_mapping, _list(cve.get("descriptions")))
            if d.get("lang") == "en"
        ),
        "",
    )
    metrics = _mapping(cve.get("metrics"))
    cwes = sorted(
        {
            _text(d.get("value"), 20)
            for w in map(_mapping, _list(cve.get("weaknesses")))
            for d in map(_mapping, _list(w.get("description")))
            if _text(d.get("value"), 20).startswith("CWE-")
        }
    )
    references = tuple(
        dict.fromkeys(
            _text(r.get("url"), 500)
            for r in map(_mapping, _list(cve.get("references")))
            if _text(r.get("url"), 500).startswith("https://")
        )
    )[:25]
    return CveRecord(
        id=cve_id,
        description=description,
        published=_datetime(cve.get("published")),
        last_modified=_datetime(cve.get("lastModified")),
        status=status,
        cvss_v31=_score(metrics, "cvssMetricV31"),
        cvss_v40=_score(metrics, "cvssMetricV40"),
        cwes=tuple(cwes),
        references=references,
        matches=_matches(cve.get("configurations")),
        kev_added=_date(cve.get("cisaExploitAdd")),
    )


def parse_page(payload: Mapping[str, Any]) -> tuple[list[CveRecord], int]:
    total = payload.get("totalResults")
    records = [
        record
        for item in _list(payload.get("vulnerabilities"))
        if (record := parse_cve(_mapping(item))) is not None
    ]
    return records, total if isinstance(total, int) else len(records)


def parse_kev(payload: Mapping[str, Any]) -> KevCatalog:
    catalog = KevCatalog(version=_text(payload.get("catalogVersion"), 40))
    for item in map(_mapping, _list(payload.get("vulnerabilities"))):
        cve_id = _text(item.get("cveID"), 32)
        if cve_id.startswith("CVE-"):
            catalog.entries[cve_id] = KevEntry(
                cve_id=cve_id,
                date_added=_date(item.get("dateAdded")),
                due_date=_date(item.get("dueDate")),
                ransomware=_text(item.get("knownRansomwareCampaignUse"), 20),
                name=_text(item.get("vulnerabilityName"), 300),
            )
    return catalog


class NvdClient:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = NVD_URL,
        transport: httpx.AsyncBaseTransport | None = None,
        min_interval: float | None = None,
        timeout: float = 60.0,
        max_retries: int = 3,
    ) -> None:
        self._api_key = api_key or None
        self._base_url = base_url
        self._transport = transport
        self._interval = min_interval if min_interval is not None else (0.7 if api_key else 6.0)
        self._timeout = timeout
        self._retries = max_retries
        self._last_request = 0.0
        self.requests = 0

    async def _get_json(self, client: httpx.AsyncClient, url: str, params: dict[str, Any]) -> Any:
        loop = asyncio.get_running_loop()
        for attempt in range(self._retries + 1):
            wait = self._last_request + self._interval - loop.time()
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = loop.time()
            self.requests += 1
            try:
                async with client.stream("GET", url, params=params) as response:
                    if response.status_code in (403, 429, 503) and attempt < self._retries:
                        await asyncio.sleep(self._interval * (attempt + 2))
                        continue
                    if response.status_code != httpx.codes.OK:
                        raise IntelError(
                            "source_error",
                            f"The intelligence source returned {response.status_code}.",
                        )
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > MAX_RESPONSE_BYTES:
                            raise IntelError(
                                "too_large", "The intelligence source sent too much data."
                            )
            except httpx.HTTPError as exc:
                if attempt < self._retries:
                    await asyncio.sleep(self._interval * (attempt + 2))
                    continue
                raise IntelError(
                    "source_unavailable", "The intelligence source is unreachable."
                ) from exc
            try:
                return json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise IntelError(
                    "invalid_data", "The intelligence source sent malformed data."
                ) from exc
        raise IntelError("rate_limited", "The intelligence source kept rejecting requests.")

    def _client(self) -> httpx.AsyncClient:
        headers = {"User-Agent": USER_AGENT}
        if self._api_key:
            headers["apiKey"] = self._api_key
        return httpx.AsyncClient(
            transport=self._transport, timeout=self._timeout, headers=headers, trust_env=False
        )

    async def iterate(self, params: Mapping[str, str]) -> AsyncIterator[CveRecord]:
        """Yield every CVE for a query, following pagination."""
        async with self._client() as client:
            start = 0
            for _ in range(MAX_PAGES):
                payload = await self._get_json(
                    client,
                    self._base_url,
                    {**params, "startIndex": start, "resultsPerPage": RESULTS_PER_PAGE},
                )
                records, total = parse_page(_mapping(payload))
                for record in records:
                    yield record
                page = len(_list(_mapping(payload).get("vulnerabilities")))
                start += page
                if page == 0 or start >= total:
                    return

    def by_product(self, vendor: str, product: str) -> AsyncIterator[CveRecord]:
        """All CVEs whose configurations reference ``vendor:product`` (any version)."""
        return self.iterate({"virtualMatchString": f"cpe:2.3:*:{vendor}:{product}"})

    async def modified_between(self, start: datetime, end: datetime) -> AsyncIterator[CveRecord]:
        """CVEs modified in ``[start, end)``, split into NVD's maximum window size."""
        cursor = start
        while cursor < end:
            window_end = min(cursor + MAX_WINDOW, end)
            async for record in self.iterate(
                {
                    "lastModStartDate": cursor.isoformat(timespec="milliseconds"),
                    "lastModEndDate": window_end.isoformat(timespec="milliseconds"),
                }
            ):
                yield record
            cursor = window_end

    async def kev(self, url: str = KEV_URL) -> KevCatalog:
        async with self._client() as client:
            return parse_kev(_mapping(await self._get_json(client, url, {})))
