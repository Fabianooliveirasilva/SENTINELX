"""Monitoring tasks (orchestrator queue).

* ``deliver`` — periodic: send due notifications from the outbox (e-mail and
  signed webhooks), with retries and exponential backoff.
* ``run_schedules`` — periodic: start due scheduled scans through the same
  checks as an interactive request (owner authority, authorization, quotas,
  emergency stop).
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.session import create_engine, create_session_factory
from app.main import build_scope_engine
from app.services.email import build_email_sender
from app.services.notifications import Deliverer, WebhookClient, deliver_due, webhook_policy
from app.services.scan_dispatch import CeleryScanDispatcher
from app.services.schedules import run_due
from sentinelx_security.scope import DnsResolver
from sentinelx_workers.celery_app import celery_app

DELIVER_TASK = "sentinelx.monitoring.deliver"
SCHEDULES_TASK = "sentinelx.monitoring.run_schedules"

logger = get_logger(__name__)


def _run(work: Callable[[AsyncSession, Settings], Awaitable[dict[str, int]]]) -> dict[str, int]:
    async def runner() -> dict[str, int]:
        settings = get_settings()
        engine = create_engine(settings)
        try:
            async with create_session_factory(engine)() as session:
                return await work(session, settings)
        finally:
            await engine.dispose()

    return asyncio.run(runner())


async def _deliver(session: AsyncSession, settings: Settings) -> dict[str, int]:
    webhooks = WebhookClient(
        DnsResolver(
            timeout_seconds=settings.dns_timeout_seconds, nameservers=settings.dns_nameservers
        ),
        webhook_policy(settings),
        timeout_seconds=settings.webhook_timeout_seconds,
    )
    deliverer = Deliverer(settings, build_email_sender(settings), webhooks)
    return await deliver_due(session, deliverer, settings)


async def _schedules(session: AsyncSession, settings: Settings) -> dict[str, int]:
    return await run_due(
        session, build_scope_engine(settings), settings, CeleryScanDispatcher(celery_app)
    )


@celery_app.task(name=DELIVER_TASK, ignore_result=True, shared=False)  # type: ignore[untyped-decorator]
def deliver() -> dict[str, int]:
    result = _run(_deliver)
    if any(result.values()):
        logger.info("notifications_delivered", **result)
    return result


@celery_app.task(name=SCHEDULES_TASK, ignore_result=True, shared=False)  # type: ignore[untyped-decorator]
def run_schedules() -> dict[str, int]:
    result = _run(_schedules)
    if any(result.values()):
        logger.info("scan_schedules_run", **result)
    return result
