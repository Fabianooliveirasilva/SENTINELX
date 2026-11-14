"""Orchestrator-side scan steps (database access, no scanning).

``start`` and ``record`` bracket the sandboxed ``execute`` step in the chain
published by the API (see ``app.services.scan_dispatch``). ``expire_stale`` is
scheduled periodically to fail jobs whose messages were lost.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.session import create_engine, create_session_factory
from app.services.scan_dispatch import RECORD_TASK, START_TASK
from app.services.scans import expire_stale_jobs, record_outcome, start_job
from sentinelx_workers.celery_app import celery_app

EXPIRE_TASK = "sentinelx.scans.expire_stale"

logger = get_logger(__name__)


def _run[T](work: Callable[[AsyncSession], Awaitable[T]]) -> T:
    async def runner() -> T:
        engine = create_engine(get_settings())
        try:
            async with create_session_factory(engine)() as session:
                return await work(session)
        finally:
            await engine.dispose()

    return asyncio.run(runner())


@celery_app.task(name=START_TASK, ignore_result=True, shared=False)  # type: ignore[untyped-decorator]
def start(job_id: str) -> dict[str, Any] | None:
    request = _run(lambda s: start_job(s, uuid.UUID(job_id), get_settings()))
    logger.info("scan_started" if request else "scan_skipped", scan_job_id=job_id)
    return request


@celery_app.task(name=RECORD_TASK, ignore_result=True, shared=False)  # type: ignore[untyped-decorator]
def record(outcome: dict[str, Any] | None, job_id: str) -> str | None:
    status = _run(lambda s: record_outcome(s, uuid.UUID(job_id), outcome))
    logger.info("scan_recorded", scan_job_id=job_id, status=status)
    return status


@celery_app.task(name=EXPIRE_TASK, ignore_result=True, shared=False)  # type: ignore[untyped-decorator]
def expire_stale() -> int:
    async def work(session: AsyncSession) -> int:
        count = await expire_stale_jobs(session, get_settings())
        await session.commit()
        return count

    return _run(work)
