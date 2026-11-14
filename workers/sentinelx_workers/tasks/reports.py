"""Report generation (orchestrator queue: database only, no network egress)."""

from __future__ import annotations

import asyncio
import uuid

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.session import create_engine, create_session_factory
from app.services.reports import REPORT_TASK, generate_report
from sentinelx_workers.celery_app import celery_app

logger = get_logger(__name__)


@celery_app.task(name=REPORT_TASK, ignore_result=True, shared=False)  # type: ignore[untyped-decorator]
def generate(report_id: str) -> str | None:
    async def work() -> str | None:
        engine = create_engine(get_settings())
        try:
            async with create_session_factory(engine)() as session:
                return await generate_report(session, uuid.UUID(report_id))
        finally:
            await engine.dispose()

    status = asyncio.run(work())
    logger.info("report_task_finished", report_id=report_id, status=status)
    return status
