"""AI analyst task (``ai`` queue, consumed only by the ``ai`` worker).

The ``ai`` worker is the only container holding the provider API key and the
only one on the ``ai-egress`` network. Without a key every analysis completes
deterministically.
"""

from __future__ import annotations

import asyncio
import uuid

from app.ai.providers import AIProvider, AnthropicProvider, ProviderUnavailableError
from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.session import create_engine, create_session_factory
from app.services.ai import AI_TASK, run_analysis
from sentinelx_workers.celery_app import celery_app

logger = get_logger(__name__)

# Provider timeout (120 s) x 2 attempts + database work must fit the soft limit.
SOFT_TIME_LIMIT = 290
TIME_LIMIT = 300


@celery_app.task(  # type: ignore[untyped-decorator]
    name=AI_TASK,
    ignore_result=True,
    shared=False,
    soft_time_limit=SOFT_TIME_LIMIT,
    time_limit=TIME_LIMIT,
)
def analyze(analysis_id: str) -> str | None:
    async def work() -> str | None:
        settings = get_settings()
        provider: AIProvider | None = None
        reason = "ai_disabled"
        if settings.ai_provider == "anthropic":
            try:
                provider = AnthropicProvider.from_settings(settings)
            except ProviderUnavailableError as exc:
                reason = exc.reason
        engine = create_engine(settings)
        try:
            async with create_session_factory(engine)() as session:
                return await run_analysis(
                    session,
                    uuid.UUID(analysis_id),
                    settings,
                    provider,
                    unavailable_reason=reason,
                )
        finally:
            await engine.dispose()

    status = asyncio.run(work())
    logger.info("ai_task_finished", analysis_id=analysis_id, status=status)
    return status
