"""Celery application.

Start a worker with::

    celery -A sentinelx_workers.celery_app:celery_app worker --loglevel=INFO

Security posture:
* JSON serialization only (pickle would allow code execution from the broker).
* Hard and soft time limits on every task; late acknowledgement so a crashed
  worker does not silently drop work; prefetch of 1 for fair scheduling of
  long-running scans.
"""

from __future__ import annotations

from typing import Any

from celery import Celery
from celery.signals import setup_logging

from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.services.scan_dispatch import ORCHESTRATOR_QUEUE

TASK_SOFT_TIME_LIMIT_SECONDS = 300
TASK_HARD_TIME_LIMIT_SECONDS = 360


def create_celery_app(settings: Settings) -> Celery:
    app = Celery(
        "sentinelx",
        broker=settings.effective_celery_broker_url,
        backend=settings.effective_celery_result_backend,
        include=[
            "sentinelx_workers.tasks.system",
            "sentinelx_workers.tasks.scans",
            "sentinelx_workers.tasks.intel",
            "sentinelx_workers.tasks.risk",
            "sentinelx_workers.tasks.monitoring",
            "sentinelx_workers.tasks.ai",
        ],
    )
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        result_accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        task_track_started=True,
        task_soft_time_limit=TASK_SOFT_TIME_LIMIT_SECONDS,
        task_time_limit=TASK_HARD_TIME_LIMIT_SECONDS,
        worker_prefetch_multiplier=1,
        worker_hijack_root_logger=False,
        result_expires=60 * 60 * 24,
        broker_connection_retry_on_startup=True,
        beat_schedule={
            "expire-stale-scan-jobs": {
                "task": "sentinelx.scans.expire_stale",
                "schedule": 300.0,
                "options": {"queue": ORCHESTRATOR_QUEUE},
            },
            "refresh-intel-products": {
                "task": "sentinelx.intel.refresh_products",
                "schedule": 6 * 3600.0,
                "options": {"queue": "intel"},
            },
            "risk-daily": {
                "task": "sentinelx.risk.daily",
                "schedule": 24 * 3600.0,
                "options": {"queue": ORCHESTRATOR_QUEUE},
            },
            "sync-epss": {
                "task": "sentinelx.intel.sync_epss",
                "schedule": 24 * 3600.0,
                "options": {"queue": "intel"},
            },
            "deliver-notifications": {
                "task": "sentinelx.monitoring.deliver",
                "schedule": 30.0,
                "options": {"queue": "notifications", "expires": 25},
            },
            "run-scan-schedules": {
                "task": "sentinelx.monitoring.run_schedules",
                "schedule": 60.0,
                "options": {"queue": ORCHESTRATOR_QUEUE, "expires": 55},
            },
            "sync-kev": {
                "task": "sentinelx.intel.sync_kev",
                "schedule": 24 * 3600.0,
                "options": {"queue": "intel"},
            },
        },
    )
    return app


@setup_logging.connect  # type: ignore[untyped-decorator]
def _configure_worker_logging(**_kwargs: Any) -> None:
    """Use the same structured, redacting logging pipeline as the API."""
    settings = get_settings()
    configure_logging(level=settings.log_level, json_logs=settings.log_json)


celery_app = create_celery_app(get_settings())
