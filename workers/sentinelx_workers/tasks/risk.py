"""Daily risk maintenance (orchestrator queue, database only).

The exposure-window factor grows with time, so every active finding is
rescored once a day and each project's posture is snapshotted for the trend.
"""

from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.session import create_engine, create_session_factory
from app.services.risk import rescore, snapshot_all
from sentinelx_workers.celery_app import celery_app

DAILY_TASK = "sentinelx.risk.daily"

logger = get_logger(__name__)


async def daily(session: AsyncSession) -> dict[str, int]:
    changed = await rescore(session, trigger="daily")
    projects = await snapshot_all(session)
    await session.commit()
    return {"changed": changed, "projects": projects}


@celery_app.task(name=DAILY_TASK, ignore_result=True, shared=False)  # type: ignore[untyped-decorator]
def run_daily() -> dict[str, int]:
    async def work() -> dict[str, int]:
        engine = create_engine(get_settings())
        try:
            async with create_session_factory(engine)() as session:
                return await daily(session)
        finally:
            await engine.dispose()

    result = asyncio.run(work())
    logger.info("risk_daily", **result)
    return result
