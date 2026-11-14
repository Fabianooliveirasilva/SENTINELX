"""Hand scan jobs to the asynchronous pipeline.

The API never imports worker code: it publishes a Celery *chain* by task name.

1. ``sentinelx.scans.start`` (orchestrator worker, has database access) re-reads
   the job, snapshots the project's current scope and marks it ``running``.
2. ``sentinelx.scans.execute`` (scanner sandbox, **no** database access or
   secrets) re-evaluates scope with fresh DNS, pins addresses and runs the scan.
3. ``sentinelx.scans.record`` (orchestrator) persists the normalized outcome.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from celery import Celery, chain, signature

from app.core.config import Settings

ORCHESTRATOR_QUEUE = "orchestrator"
SCANNER_QUEUE = "scans"
# ZAP drives a single shared daemon, so its scans are serialized on their own queue.
ZAP_QUEUE = "scans.zap"
START_TASK = "sentinelx.scans.start"
EXECUTE_TASK = "sentinelx.scans.execute"
RECORD_TASK = "sentinelx.scans.record"
# Extra time the Celery hard limit grants beyond the scan's own timeout.
TIME_LIMIT_GRACE_SECONDS = 60


@dataclass(frozen=True, slots=True)
class DispatchHandle:
    execute_task_id: str


INTEL_QUEUE = "intel"
INTEL_REFRESH_TASK = "sentinelx.intel.refresh_products"


class IntelDispatcher(Protocol):
    def refresh_products(self) -> None: ...


class CeleryIntelDispatcher:
    def __init__(self, app: Celery) -> None:
        self._app = app

    def refresh_products(self) -> None:
        self._app.send_task(INTEL_REFRESH_TASK, queue=INTEL_QUEUE, retry=False)


class ScanDispatcher(Protocol):
    def dispatch(self, job_id: str, scanner: str, timeout_seconds: int) -> DispatchHandle: ...

    def revoke(self, task_id: str) -> None: ...


def create_producer(settings: Settings) -> Celery:
    """A Celery app used only to publish messages (no tasks are registered)."""
    app = Celery(
        "sentinelx",
        broker=settings.effective_celery_broker_url,
        backend=settings.effective_celery_result_backend,
    )
    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_accept_content=["json"],
        broker_connection_retry=False,
        broker_connection_max_retries=0,
        broker_transport_options={"max_retries": 1, "socket_timeout": 3},
    )
    return app


class CeleryScanDispatcher:
    def __init__(self, app: Celery) -> None:
        self._app = app

    def dispatch(self, job_id: str, scanner: str, timeout_seconds: int) -> DispatchHandle:
        execute = signature(
            EXECUTE_TASK,
            app=self._app,
            queue=ZAP_QUEUE if scanner == "zap" else SCANNER_QUEUE,
            soft_time_limit=timeout_seconds + TIME_LIMIT_GRACE_SECONDS // 2,
            time_limit=timeout_seconds + TIME_LIMIT_GRACE_SECONDS,
        )
        workflow = chain(
            signature(START_TASK, args=(job_id,), app=self._app, queue=ORCHESTRATOR_QUEUE),
            execute,
            signature(RECORD_TASK, args=(job_id,), app=self._app, queue=ORCHESTRATOR_QUEUE),
        )
        result = workflow.apply_async()
        # The chain's result is the last step; its parent is the execute step,
        # whose id is kept so a cancellation can terminate it.
        parent = result.parent
        if parent is None:  # pragma: no cover - Celery invariant for 3-step chains
            raise RuntimeError("chain published without its parent steps")
        return DispatchHandle(execute_task_id=str(parent.id))

    def revoke(self, task_id: str) -> None:
        self._app.control.revoke(task_id, terminate=True, signal="SIGTERM")
