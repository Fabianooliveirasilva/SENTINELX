from __future__ import annotations

from sentinelx_workers.celery_app import (
    TASK_HARD_TIME_LIMIT_SECONDS,
    TASK_SOFT_TIME_LIMIT_SECONDS,
    celery_app,
)
from sentinelx_workers.tasks.system import ping


def test_only_json_serialization_is_accepted() -> None:
    conf = celery_app.conf

    assert conf.task_serializer == "json"
    assert conf.result_serializer == "json"
    assert list(conf.accept_content) == ["json"]
    assert list(conf.result_accept_content) == ["json"]


def test_tasks_have_time_limits_and_safe_ack_semantics() -> None:
    conf = celery_app.conf

    assert conf.task_soft_time_limit == TASK_SOFT_TIME_LIMIT_SECONDS
    assert conf.task_time_limit == TASK_HARD_TIME_LIMIT_SECONDS
    assert TASK_SOFT_TIME_LIMIT_SECONDS < TASK_HARD_TIME_LIMIT_SECONDS
    assert conf.task_acks_late is True
    assert conf.worker_prefetch_multiplier == 1


def test_ping_task_is_registered_and_executes() -> None:
    assert "system.ping" in celery_app.tasks

    result = ping.apply().get()

    assert result["status"] == "ok"
    assert result["worker"]
    assert result["timestamp"].endswith("+00:00")
