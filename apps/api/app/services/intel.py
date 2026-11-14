"""Threat-intelligence persistence and correlation.

* **Inventory** — every completed scan replaces the software components that scan
  type reported for the asset (stale components disappear with the next scan).
* **Product-driven sync** — each correlatable ``vendor:product`` seen in an
  inventory gets an ``intel_product_syncs`` row; the intel worker fetches its CVEs
  from NVD when the row is pending or older than the TTL. SentinelX therefore
  stores the CVEs relevant to what it has observed, not the whole NVD.
* **Correlation** — components are matched against stored CPE ranges and fed
  through the normal finding lifecycle (source ``intel``, profile
  ``cve:<scanner>``), so fixed versions auto-resolve and analyst decisions stick.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, delete, func, or_, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError
from app.models import (
    Cve,
    CveMatch,
    Finding,
    IntelSource,
    ProductSync,
    ScanJob,
    SoftwareComponent,
)
from app.repositories.sql import LIKE_ESCAPE, contains_pattern
from app.schemas.pagination import PageParams
from app.services.events import EventType, emit
from app.services.findings import (
    ACTIVE_FINDING_STATUSES,
    IngestResult,
    IngestScope,
    ingest_candidates,
)
from sentinelx_security.intel.correlate import SoftwareComponent as Component
from sentinelx_security.intel.correlate import correlate, extract_components
from sentinelx_security.intel.cpe import CpeRange
from sentinelx_security.intel.nvd import CveRecord, CvssScore, KevCatalog

INTEL_SOURCE = "intel"


def utcnow() -> datetime:
    return datetime.now(UTC)


def intel_profile(scanner: str) -> str:
    return f"cve:{scanner}"


# --------------------------------------------------------------------- inventory


def _component(row: SoftwareComponent) -> Component:
    cpes = tuple(tuple(c.split(":", 1)) for c in row.cpes if ":" in c)
    return Component(
        name=row.name,
        version=row.version,
        update=row.update,
        cpes=tuple((v, p) for v, p in cpes),
        location=row.location,
        source_kind=row.source,
        raw_version=row.raw_version,
    )


async def record_components(
    session: AsyncSession, job: ScanJob, observations: Sequence[dict[str, Any]]
) -> list[SoftwareComponent]:
    """Replace the asset's inventory for this scanner with what the scan observed."""
    now = utcnow()
    components = extract_components(observations)
    await session.execute(
        delete(SoftwareComponent).where(
            SoftwareComponent.asset_id == job.asset_id, SoftwareComponent.source == job.scanner
        )
    )
    rows = [
        SoftwareComponent(
            project_id=job.project_id,
            asset_id=job.asset_id,
            source=job.scanner,
            name=c.name,
            version=c.version,
            update=c.update,
            raw_version=c.raw_version,
            cpes=[f"{v}:{p}" for v, p in c.cpes],
            location=c.location,
            correlatable=c.correlatable,
            first_seen_at=now,
            last_seen_at=now,
            last_scan_job_id=job.id,
        )
        for c in components
    ]
    session.add_all(rows)
    await session.flush()
    products = {tuple(cpe.split(":", 1)) for row in rows if row.correlatable for cpe in row.cpes}
    for vendor, product in products:
        if await session.get(ProductSync, (vendor, product)) is None:
            session.add(ProductSync(vendor=vendor, product=product, status="pending"))
    await session.flush()
    return rows


async def stale_products(
    session: AsyncSession, ttl: timedelta, limit: int, only: Iterable[tuple[str, str]] = ()
) -> list[tuple[str, str]]:
    cutoff = utcnow() - ttl
    stmt = select(ProductSync.vendor, ProductSync.product).where(
        or_(ProductSync.synced_at.is_(None), ProductSync.synced_at < cutoff)
    )
    wanted = list(only)
    if wanted:
        stmt = stmt.where(tuple_(ProductSync.vendor, ProductSync.product).in_(wanted))
    rows = await session.execute(stmt.order_by(ProductSync.requested_at).limit(limit))
    return [(v, p) for v, p in rows.all()]


# --------------------------------------------------------------------- CVE store


def _score(
    version: str | None, vector: str | None, score: float | None, sev: str | None
) -> CvssScore | None:
    if score is None:
        return None
    return CvssScore(version or "", vector or "", score, sev or "")


def to_record(cve: Cve, matches: Sequence[CveMatch]) -> CveRecord:
    return CveRecord(
        id=cve.id,
        description=cve.description,
        published=cve.published_at,
        last_modified=cve.last_modified_at,
        status=cve.status,
        cvss_v31=_score("3.1", cve.cvss31_vector, cve.cvss31_score, cve.cvss_severity),
        cvss_v40=_score("4.0", cve.cvss40_vector, cve.cvss40_score, cve.cvss_severity),
        cwes=tuple(cve.cwes),
        references=tuple(cve.references),
        matches=tuple(
            CpeRange(
                criteria=m.criteria,
                vendor=m.vendor,
                product=m.product,
                version=m.version,
                update=m.update,
                start_including=m.start_including,
                start_excluding=m.start_excluding,
                end_including=m.end_including,
                end_excluding=m.end_excluding,
            )
            for m in matches
        ),
        kev_added=cve.kev_added_on,
    )


async def upsert_cves(session: AsyncSession, records: Iterable[CveRecord]) -> int:
    count = 0
    now = utcnow()
    for record in records:
        cve = await session.get(Cve, record.id)
        if cve is None:
            cve = Cve(id=record.id)
            session.add(cve)
        preferred = record.cvss
        cve.description = record.description
        cve.status = record.status
        cve.published_at = record.published
        cve.last_modified_at = record.last_modified
        cve.cvss_version = preferred.version if preferred else None
        cve.cvss_vector = preferred.vector if preferred else None
        cve.cvss_score = preferred.score if preferred else None
        cve.cvss_severity = preferred.severity if preferred else None
        cve.cvss31_vector = record.cvss_v31.vector if record.cvss_v31 else None
        cve.cvss31_score = record.cvss_v31.score if record.cvss_v31 else None
        cve.cvss40_vector = record.cvss_v40.vector if record.cvss_v40 else None
        cve.cvss40_score = record.cvss_v40.score if record.cvss_v40 else None
        cve.cwes = list(record.cwes)
        cve.references = list(record.references)
        if record.kev_added and cve.kev_added_on is None:
            cve.kev_added_on = record.kev_added
        cve.fetched_at = now
        await session.flush()
        await session.execute(delete(CveMatch).where(CveMatch.cve_id == record.id))
        session.add_all(
            CveMatch(
                cve_id=record.id,
                criteria=m.criteria[:500],
                vendor=m.vendor[:200],
                product=m.product[:200],
                version=m.version[:100],
                update=m.update[:100],
                start_including=m.start_including,
                start_excluding=m.start_excluding,
                end_including=m.end_including,
                end_excluding=m.end_excluding,
            )
            for m in record.matches
        )
        count += 1
    await session.flush()
    return count


async def _kev_events(session: AsyncSession, cve_ids: list[str], catalog: KevCatalog) -> None:
    """One event per active finding whose CVE has just entered the KEV catalog."""
    if not cve_ids:
        return
    findings = (
        (
            await session.execute(
                select(Finding).where(
                    Finding.cve_id.in_(cve_ids), Finding.status.in_(ACTIVE_FINDING_STATUSES)
                )
            )
        )
        .scalars()
        .all()
    )
    for finding in findings:
        entry = catalog.entries[finding.cve_id or ""]
        ransomware = entry.ransomware.strip().lower() == "known"
        await emit(
            session,
            project_id=finding.project_id,
            event_type=EventType.FINDING_KEV_LISTED,
            severity="critical" if ransomware else "high",
            title=f"{finding.cve_id} is known to be exploited (CISA KEV): {finding.title}",
            asset_id=finding.asset_id,
            finding_id=finding.id,
            details={
                "cve_id": finding.cve_id,
                "kev_added_on": entry.date_added.isoformat() if entry.date_added else None,
                "kev_due_on": entry.due_date.isoformat() if entry.due_date else None,
                "ransomware_campaign_use": entry.ransomware or None,
                "catalog_version": catalog.version,
            },
        )


async def apply_kev(session: AsyncSession, catalog: KevCatalog) -> int:
    """Flag stored CVEs present in the KEV catalog. Returns how many are flagged."""
    if not catalog.entries:
        return 0
    rows = (
        (await session.execute(select(Cve).where(Cve.id.in_(list(catalog.entries)))))
        .scalars()
        .all()
    )
    newly_listed: list[str] = []
    for cve in rows:
        entry = catalog.entries[cve.id]
        if cve.kev_added_on is None and entry.date_added is not None:
            newly_listed.append(cve.id)
        cve.kev_added_on = entry.date_added or cve.kev_added_on
        cve.kev_due_on = entry.due_date
        cve.kev_ransomware = entry.ransomware or None
    await _kev_events(session, newly_listed, catalog)
    await set_source(
        session, "kev", status="ok", version=catalog.version, records=len(catalog.entries)
    )
    return len(rows)


async def set_source(
    session: AsyncSession,
    name: str,
    *,
    status: str,
    version: str | None = None,
    records: int | None = None,
    error: str | None = None,
) -> None:
    source = await session.get(IntelSource, name)
    if source is None:
        source = IntelSource(name=name)
        session.add(source)
    source.status = status
    source.error = error[:300] if error else None
    if status == "ok":
        source.synced_at = utcnow()
    if version is not None:
        source.version = version[:64]
    if records is not None:
        source.records = records
    await session.flush()


async def mark_product(
    session: AsyncSession,
    vendor: str,
    product: str,
    *,
    status: str,
    count: int = 0,
    error: str | None = None,
) -> None:
    row = await session.get(ProductSync, (vendor, product))
    if row is None:
        row = ProductSync(vendor=vendor, product=product)
        session.add(row)
    row.status = status
    row.error = error[:300] if error else None
    if status == "ok":
        row.synced_at = utcnow()
        row.cve_count = count
    await session.flush()


# --------------------------------------------------------------------- correlation


async def _records_for(session: AsyncSession, pairs: set[tuple[str, str]]) -> list[CveRecord]:
    if not pairs:
        return []
    cve_ids = (
        (
            await session.execute(
                select(CveMatch.cve_id)
                .where(tuple_(CveMatch.vendor, CveMatch.product).in_(list(pairs)))
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    if not cve_ids:
        return []
    cves = (await session.execute(select(Cve).where(Cve.id.in_(cve_ids)))).scalars().all()
    matches = (
        (await session.execute(select(CveMatch).where(CveMatch.cve_id.in_(cve_ids))))
        .scalars()
        .all()
    )
    by_cve: dict[str, list[CveMatch]] = {}
    for match in matches:
        by_cve.setdefault(match.cve_id, []).append(match)
    return [to_record(cve, by_cve.get(cve.id, [])) for cve in cves]


async def correlate_asset(
    session: AsyncSession,
    project_id: uuid.UUID,
    asset_id: uuid.UUID,
    scanner: str,
    scan_job_id: uuid.UUID | None,
) -> IngestResult:
    rows = (
        (
            await session.execute(
                select(SoftwareComponent).where(
                    SoftwareComponent.asset_id == asset_id, SoftwareComponent.source == scanner
                )
            )
        )
        .scalars()
        .all()
    )
    components = [_component(r) for r in rows]
    pairs = {pair for c in components if c.correlatable for pair in c.cpes}
    candidates = correlate(components, await _records_for(session, pairs))
    return await ingest_candidates(
        session,
        IngestScope(project_id, asset_id, INTEL_SOURCE, intel_profile(scanner), scan_job_id),
        candidates,
    )


async def recorrelate_products(session: AsyncSession, products: Iterable[tuple[str, str]]) -> int:
    """Re-run correlation for every asset whose inventory contains these products."""
    keys = [f"{v}:{p}" for v, p in products]
    if not keys:
        return 0
    targets = (
        await session.execute(
            select(
                SoftwareComponent.project_id, SoftwareComponent.asset_id, SoftwareComponent.source
            )
            .where(SoftwareComponent.cpes.overlap(keys))
            .distinct()
        )
    ).all()
    for project_id, asset_id, source in targets:
        await correlate_asset(session, project_id, asset_id, source, None)
    return len(targets)


# --------------------------------------------------------------------- API service


@dataclass(frozen=True, slots=True)
class CveFilters:
    search: str | None = None
    severity: str | None = None
    kev: bool | None = None
    vendor: str | None = None
    product: str | None = None


class IntelService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def search(self, params: PageParams, filters: CveFilters) -> tuple[Sequence[Cve], int]:
        stmt = select(Cve)
        if filters.search:
            term = filters.search.strip()
            if term.upper().startswith("CVE-"):
                stmt = stmt.where(Cve.id.ilike(contains_pattern(term.upper()), escape=LIKE_ESCAPE))
            else:
                stmt = stmt.where(Cve.description.ilike(contains_pattern(term), escape=LIKE_ESCAPE))
        if filters.severity:
            stmt = stmt.where(Cve.cvss_severity == filters.severity)
        if filters.kev is True:
            stmt = stmt.where(Cve.kev_added_on.is_not(None))
        if filters.vendor or filters.product:
            conditions = []
            if filters.vendor:
                conditions.append(CveMatch.vendor == filters.vendor.lower())
            if filters.product:
                conditions.append(CveMatch.product == filters.product.lower())
            stmt = stmt.where(Cve.id.in_(select(CveMatch.cve_id).where(and_(*conditions))))
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )
        rows = (
            (
                await self._session.execute(
                    stmt.order_by(Cve.cvss_score.desc().nulls_last(), Cve.id.desc())
                    .offset(params.offset)
                    .limit(params.page_size)
                )
            )
            .scalars()
            .all()
        )
        return rows, total

    async def get(self, cve_id: str) -> tuple[Cve, Sequence[CveMatch]]:
        cve = await self._session.get(Cve, cve_id.upper())
        if cve is None:
            raise NotFoundError("CVE not found in the local intelligence store.")
        matches = (
            (
                await self._session.execute(
                    select(CveMatch).where(CveMatch.cve_id == cve.id).order_by(CveMatch.criteria)
                )
            )
            .scalars()
            .all()
        )
        return cve, matches

    async def status(self) -> dict[str, Any]:
        sources = (await self._session.execute(select(IntelSource))).scalars().all()
        products = (
            (await self._session.execute(select(ProductSync).order_by(ProductSync.vendor)))
            .scalars()
            .all()
        )
        totals = (
            await self._session.execute(
                select(func.count(), func.count(Cve.kev_added_on)).select_from(Cve)
            )
        ).one()
        return {
            "cves": int(totals[0]),
            "kev_cves": int(totals[1]),
            "sources": sources,
            "products": products,
        }

    async def request_product(self, vendor: str, product: str) -> ProductSync:
        row = await self._session.get(ProductSync, (vendor.lower(), product.lower()))
        if row is None:
            row = ProductSync(vendor=vendor.lower(), product=product.lower())
            self._session.add(row)
        row.status = "pending"
        row.requested_at = utcnow()
        row.synced_at = None
        await self._session.commit()
        return row
