"""Celery application.

When ``REDIS_URL`` is configured, tasks are dispatched to a separate worker
process (production). Otherwise Celery runs eagerly in-process so scans still
work for local development and tests with no broker.
"""
from __future__ import annotations

from celery import Celery

from app.core.config import settings

_use_broker = bool(settings.redis_url)

celery_app = Celery(
    "sentinelx",
    broker=settings.redis_url or "memory://",
    backend=settings.redis_url or "cache+memory://",
)

celery_app.conf.update(
    task_always_eager=not _use_broker,
    task_eager_propagates=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    worker_max_tasks_per_child=100,
)

# Ensure task modules are registered.
celery_app.autodiscover_tasks(["app.worker"])
import app.worker.tasks  # noqa: E402,F401
