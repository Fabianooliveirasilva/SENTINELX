"""Threat-intelligence tasks (queue ``intel``; the only worker with feed egress).

* ``enrich(job_id)`` — after a scan is recorded: refresh the stale products in
  that asset's inventory from NVD, then re-correlate the affected assets.
* ``refresh_products`` — periodic: refresh the oldest stale products.
* ``sync_kev`` — periodic: apply the CISA KEV catalog to stored CVEs.

Failures never break scans: they are recorded on the sync rows and retried by
the next run.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.session import create_engine, create_session_factory
from app.models import Cve, Finding, ScanJob, SoftwareComponent
from app.services.intel import (
    apply_kev,
    mark_product,
    recorrelate_products,
    set_source,
    stale_products,
    upsert_cves,
)
from app.services.risk import rescore, snapshot_all
from sentinelx_security.intel.epss import EPSS_URL, EpssScore, fetch_epss
from sentinelx_security.intel.nvd import CveRecord, IntelError, NvdClient
from sentinelx_workers.celery_app import celery_app

INTEL_QUEUE = "intel"
ENRICH_TASK = "sentinelx.intel.enrich"
REFRESH_TASK = "sentinelx.intel.refresh_products"
KEV_TASK = "sentinelx.intel.sync_kev"
EPSS_TASK = "sentinelx.intel.sync_epss"
MAX_CVES_PER_PRODUCT = 5000

logger = get_logger(__name__)


def nvd_client(settings: Settings) -> NvdClient:
    key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None
    return NvdClient(api_key=key, base_url=settings.nvd_base_url)


async def _run_db[T](work: Callable[[AsyncSession], Awaitable[T]]) -> T:
    engine = create_engine(get_settings())
    try:
        async with create_session_factory(engine)() as session:
            return await work(session)
    finally:
        await engine.dispose()


async def refresh(
    products: list[tuple[str, str]], client: NvdClient, session: AsyncSession
) -> dict[str, Any]:
    """Fetch, store and re-correlate the given products. Commits per product."""
    refreshed: list[tuple[str, str]] = []
    errors: dict[str, str] = {}
    for vendor, product in products:
        try:
            records: list[CveRecord] = []
            async for record in client.by_product(vendor, product):
                records.append(record)
                if len(records) >= MAX_CVES_PER_PRODUCT:
                    break
        except IntelError as exc:
            errors[f"{vendor}:{product}"] = exc.code
            await mark_product(session, vendor, product, status="error", error=exc.message)
            await session.commit()
            continue
        await upsert_cves(session, records)
        await mark_product(session, vendor, product, status="ok", count=len(records))
        await session.commit()
        refreshed.append((vendor, product))
    assets = await recorrelate_products(session, refreshed)
    await session.commit()
    return {"refreshed": len(refreshed), "errors": errors, "assets_recorrelated": assets}


async def enrich_job(
    job_id: uuid.UUID, settings: Settings, client: NvdClient, session: AsyncSession
) -> dict[str, Any]:
    job = await session.get(ScanJob, job_id)
    if job is None:
        return {"refreshed": 0}
    cpes = (
        (
            await session.execute(
                select(SoftwareComponent.cpes).where(
                    SoftwareComponent.asset_id == job.asset_id,
                    SoftwareComponent.source == job.scanner,
                    SoftwareComponent.correlatable.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    wanted = {tuple(c.split(":", 1)) for row in cpes for c in row if ":" in c}
    products = await stale_products(
        session,
        timedelta(hours=settings.intel_product_ttl_hours),
        settings.intel_max_products_per_run,
        only=[(v, p) for v, p in wanted],
    )
    return await refresh(products, client, session)


@celery_app.task(name=ENRICH_TASK, ignore_result=True, shared=False)  # type: ignore[untyped-decorator]
def enrich(job_id: str) -> dict[str, Any]:
    settings = get_settings()
    if not settings.intel_enabled:
        return {"skipped": True}
    result = asyncio.run(
        _run_db(lambda s: enrich_job(uuid.UUID(job_id), settings, nvd_client(settings), s))
    )
    logger.info("intel_enriched", scan_job_id=job_id, **result)
    return result


@celery_app.task(name=REFRESH_TASK, ignore_result=True, shared=False)  # type: ignore[untyped-decorator]
def refresh_products() -> dict[str, Any]:
    settings = get_settings()
    if not settings.intel_enabled:
        return {"skipped": True}

    async def work(session: AsyncSession) -> dict[str, Any]:
        products = await stale_products(
            session,
            timedelta(hours=settings.intel_product_ttl_hours),
            settings.intel_max_products_per_run,
        )
        return await refresh(products, nvd_client(settings), session)

    result = asyncio.run(_run_db(work))
    logger.info("intel_products_refreshed", **result)
    return result


@celery_app.task(name=KEV_TASK, ignore_result=True, shared=False)  # type: ignore[untyped-decorator]
def sync_kev() -> int:
    settings = get_settings()
    if not settings.intel_enabled:
        return 0

    async def work(session: AsyncSession) -> int:
        try:
            catalog = await nvd_client(settings).kev(settings.kev_url)
        except IntelError as exc:
            await set_source(session, "kev", status="error", error=exc.message)
            await session.commit()
            return 0
        flagged = await apply_kev(session, catalog)
        await rescore(session, trigger="intel_updated", cve_ids=list(catalog.entries))
        await snapshot_all(session)
        await session.commit()
        return flagged

    flagged = asyncio.run(_run_db(work))
    logger.info("intel_kev_synced", flagged=flagged)
    return flagged


async def apply_epss(session: AsyncSession, scores: dict[str, EpssScore]) -> int:
    rows = (
        (await session.execute(select(Cve).where(Cve.id.in_(list(scores))))).scalars().all()
        if scores
        else []
    )
    for cve in rows:
        entry = scores[cve.id]
        cve.epss_score = entry.probability
        cve.epss_percentile = entry.percentile
        cve.epss_scored_on = entry.scored_on
    await session.flush()
    return len(rows)


async def sync_epss_for_findings(
    session: AsyncSession, fetch: Any = fetch_epss, url: str = EPSS_URL
) -> int:
    """EPSS for every CVE referenced by an open or acknowledged finding."""
    cve_ids = (
        (
            await session.execute(
                select(Finding.cve_id)
                .where(Finding.cve_id.is_not(None), Finding.status.in_(("open", "acknowledged")))
                .distinct()
            )
        )
        .scalars()
        .all()
    )
    ids = [c for c in cve_ids if c]
    if not ids:
        return 0
    try:
        scores = await fetch(ids, url=url)
    except IntelError as exc:
        await set_source(session, "epss", status="error", error=exc.message)
        await session.commit()
        return 0
    updated = await apply_epss(session, scores)
    await set_source(session, "epss", status="ok", records=updated)
    await rescore(session, trigger="intel_updated", cve_ids=ids)
    await snapshot_all(session)
    await session.commit()
    return updated


@celery_app.task(name=EPSS_TASK, ignore_result=True, shared=False)  # type: ignore[untyped-decorator]
def sync_epss() -> int:
    settings = get_settings()
    if not settings.intel_enabled:
        return 0
    updated = asyncio.run(_run_db(lambda s: sync_epss_for_findings(s, url=settings.epss_url)))
    logger.info("intel_epss_synced", updated=updated)
    return updated
