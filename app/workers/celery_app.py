"""Optional Celery integration.

Why optional
------------
The in-process :class:`~app.workers.queue.JobQueue` covers single-node
deployments and every test.  Celery is what you want when jobs must survive a
restart, be distributed across machines, or be scheduled — and it brings a
broker with it, so it stays an extra rather than a dependency.

The task surface is identical: the same registered job functions are wrapped,
so switching backends is a configuration change, not a code change.

Run a worker with::

    celery -A app.workers.celery_app worker --loglevel=INFO --concurrency=2

Operational note
----------------
``worker_max_tasks_per_child`` is set deliberately: log-processing jobs build
large Arrow buffers, and recycling the worker process after a bounded number of
tasks is the simplest defence against fragmentation-driven RSS growth.
"""

from __future__ import annotations

from typing import Any

from app.core.config import get_settings
from app.core.exceptions import ConfigurationError
from app.core.logging import configure_from_settings, get_logger

log = get_logger(__name__)


def build_celery_app() -> Any:
    """Construct the Celery application from configuration."""
    try:
        from celery import Celery
    except ImportError as exc:  # pragma: no cover - optional extra
        raise ConfigurationError(
            "celery is not installed; install with pip install 'big-data-log-analytics[celery]'"
        ) from exc

    settings = get_settings()
    broker = settings.workers.broker_url or settings.cache.redis_url()
    configure_from_settings(settings)

    app = Celery("log_analytics", broker=broker, backend=broker)
    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        # JSON only: a broker that can deliver pickled payloads is a remote
        # code execution primitive if anything can write to it.
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_acks_late=True,  # redeliver if a worker dies mid-task
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,  # long tasks: do not hoard the queue
        worker_max_tasks_per_child=50,
        task_time_limit=int(settings.workers.job_timeout_seconds),
        task_soft_time_limit=int(settings.workers.job_timeout_seconds * 0.9),
        result_expires=settings.workers.result_ttl_seconds,
        broker_connection_retry_on_startup=True,
    )
    _register_tasks(app)
    return app


def _register_tasks(app: Any) -> None:
    """Expose the registered job functions as Celery tasks."""
    from app.workers import jobs

    for name, func in (
        ("ingest", jobs.ingest_job),
        ("ingest_directory", jobs.ingest_directory_job),
        ("report", jobs.report_job),
        ("detect_anomalies", jobs.detect_anomalies_job),
        ("security_scan", jobs.security_scan_job),
        ("cleanup", jobs.cleanup_job),
        ("compact", jobs.compact_job),
        ("generate_data", jobs.generate_data_job),
    ):
        app.task(name=f"loganalytics.{name}", bind=False)(func)


#: Module-level app for ``celery -A app.workers.celery_app``.  Built lazily so
#: importing this module without Celery installed does not explode.
celery_app: Any = None

try:  # pragma: no cover - depends on an optional extra
    celery_app = build_celery_app()
except Exception:  # noqa: BLE001 - absence of celery is not an error here
    log.debug("celery application not built (celery not installed or not configured)")


__all__ = ["build_celery_app", "celery_app"]
