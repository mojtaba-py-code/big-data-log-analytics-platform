"""Background job queue.

Responsibility
--------------
Run expensive operations — ingesting a multi-gigabyte file, generating a
report, scanning for anomalies — outside the request/response cycle, with
status tracking, retries and cancellation.

Why an in-process queue
-----------------------
A hard Celery dependency would force a broker onto every deployment, including
a laptop demo.  :class:`JobQueue` is a thread-pool executor with a job registry
and the same submit/status/result surface Celery exposes, so
:mod:`app.workers.celery_app` can swap in for a distributed deployment without
any caller changing.

Threads, not processes, here: these jobs are dominated by I/O (reading files,
writing Parquet, querying DuckDB) and DuckDB/pyarrow release the GIL during
their heavy work.  CPU-bound *parsing* parallelism is handled separately by
:mod:`app.pipeline.parallel`, which does use processes.

Durability
----------
Job state lives in memory; a restart loses queued work.  That is an explicit
trade-off for the default deployment — the metadata store records what each run
did, so a lost job is visible and re-submittable.  Use the Celery backend when
at-least-once delivery across restarts is required.
"""

from __future__ import annotations

import contextlib
import threading
import time
import traceback
import uuid
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.core.exceptions import JobError
from app.core.logging import get_logger, set_request_id
from app.core.timeutil import to_iso, utcnow
from app.models.enums import JobStatus

log = get_logger(__name__)

#: Registered job handlers, by name.  Submitting a job by name (rather than by
#: callable) means an API request can never schedule arbitrary code.
_HANDLERS: dict[str, Callable[..., Any]] = {}


def register_job(name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator that makes a function submittable by name."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        if name in _HANDLERS:
            raise ValueError(f"job {name!r} is already registered")
        _HANDLERS[name] = func
        return func

    return decorator


def available_jobs() -> list[str]:
    return sorted(_HANDLERS)


@dataclass
class Job:
    """A unit of background work and everything known about it."""

    id: str
    name: str
    status: JobStatus = JobStatus.PENDING
    created_at: datetime = field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    attempts: int = 0
    max_retries: int = 0
    result: Any = None
    error: str | None = None
    progress: float = 0.0
    kwargs: dict[str, Any] = field(default_factory=dict)
    _future: Future[Any] | None = field(default=None, repr=False)

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at is None:
            return None
        end = self.finished_at or utcnow()
        return (end - self.started_at).total_seconds()

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "status": str(self.status),
            "created_at": to_iso(self.created_at),
            "started_at": to_iso(self.started_at) if self.started_at else None,
            "finished_at": to_iso(self.finished_at) if self.finished_at else None,
            "duration_seconds": round(self.duration_seconds, 3)
            if self.duration_seconds is not None
            else None,
            "attempts": self.attempts,
            "progress": round(self.progress, 4),
            "error": self.error,
            "result": _summarise(self.result),
        }


def _summarise(result: Any) -> Any:
    """Keep job listings small — a full result can be megabytes."""
    if result is None or isinstance(result, (str, int, float, bool)):
        return result
    if hasattr(result, "summary"):
        return result.summary()
    if isinstance(result, dict):
        return dict(list(result.items())[:20])
    if isinstance(result, list):
        return {"items": len(result)}
    return str(result)[:500]


class JobQueue:
    """Thread-pool job queue with retries and bounded history."""

    def __init__(
        self,
        *,
        concurrency: int = 2,
        max_history: int = 500,
        default_max_retries: int = 2,
        retry_backoff_seconds: float = 1.0,
    ) -> None:
        self.concurrency = max(1, concurrency)
        self.max_history = max(10, max_history)
        self.default_max_retries = default_max_retries
        self.retry_backoff_seconds = retry_backoff_seconds
        self._executor = ThreadPoolExecutor(
            max_workers=self.concurrency, thread_name_prefix="loga-worker"
        )
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._lock = threading.RLock()
        self._shutdown = False

    # -- submission ---------------------------------------------------------- #
    def submit(self, name: str, *, max_retries: int | None = None, **kwargs: Any) -> Job:
        """Queue a registered job for execution."""
        if self._shutdown:
            raise JobError("the job queue is shutting down")
        handler = _HANDLERS.get(name)
        if handler is None:
            raise JobError(f"unknown job {name!r}", available=available_jobs())

        job = Job(
            id=uuid.uuid4().hex[:16],
            name=name,
            kwargs=dict(kwargs),
            max_retries=self.default_max_retries if max_retries is None else max_retries,
        )
        with self._lock:
            self._jobs[job.id] = job
            self._prune()
        job._future = self._executor.submit(self._run, job, handler)
        log.info("job submitted", extra={"job_id": job.id, "job": name})
        return job

    def _run(self, job: Job, handler: Callable[..., Any]) -> Any:
        """Execute a job with retries and exponential backoff."""
        set_request_id(job.id)
        job.status = JobStatus.RUNNING
        job.started_at = utcnow()

        for attempt in range(1, job.max_retries + 2):
            job.attempts = attempt
            try:
                result = handler(**job.kwargs)
            except Exception as exc:  # noqa: BLE001 - recorded on the job
                if attempt > job.max_retries:
                    job.status = JobStatus.FAILED
                    job.finished_at = utcnow()
                    job.error = f"{type(exc).__name__}: {exc}"
                    log.error(
                        "job failed",
                        extra={
                            "job_id": job.id,
                            "job": job.name,
                            "attempts": attempt,
                            "error_type": type(exc).__name__,
                            "traceback": traceback.format_exc(limit=5),
                        },
                    )
                    return None
                job.status = JobStatus.RETRYING
                delay = self.retry_backoff_seconds * (2 ** (attempt - 1))
                log.warning(
                    "job failed, retrying",
                    extra={"job_id": job.id, "attempt": attempt, "delay": delay},
                )
                time.sleep(delay)
                continue

            job.status = JobStatus.SUCCEEDED
            job.finished_at = utcnow()
            job.progress = 1.0
            job.result = result
            log.info(
                "job completed",
                extra={
                    "job_id": job.id,
                    "job": job.name,
                    "duration": round(job.duration_seconds or 0.0, 3),
                },
            )
            return result
        return None  # pragma: no cover - loop always returns

    # -- inspection ---------------------------------------------------------- #
    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self, *, limit: int = 50, status: JobStatus | None = None) -> list[Job]:
        with self._lock:
            jobs = list(self._jobs.values())
        if status is not None:
            jobs = [job for job in jobs if job.status == status]
        return sorted(jobs, key=lambda j: j.created_at, reverse=True)[:limit]

    def wait(self, job_id: str, timeout: float | None = None) -> Job | None:
        """Block until a job finishes — used by the CLI's ``--wait`` flag."""
        job = self.get(job_id)
        if job is None or job._future is None:
            return job
        with contextlib.suppress(Exception):  # the failure is recorded on the job
            job._future.result(timeout=timeout)
        return job

    def cancel(self, job_id: str) -> bool:
        """Cancel a job that has not started yet.

        A running job cannot be interrupted safely — killing a thread mid-write
        would leave a partial Parquet file — so cancellation only applies to
        queued work.
        """
        job = self.get(job_id)
        if job is None or job._future is None:
            return False
        if job._future.cancel():
            job.status = JobStatus.CANCELLED
            job.finished_at = utcnow()
            return True
        return False

    def stats(self) -> dict[str, Any]:
        with self._lock:
            jobs = list(self._jobs.values())
        counts: dict[str, int] = {}
        for job in jobs:
            counts[str(job.status)] = counts.get(str(job.status), 0) + 1
        return {
            "concurrency": self.concurrency,
            "tracked": len(jobs),
            "by_status": counts,
            "registered_jobs": available_jobs(),
        }

    def _prune(self) -> None:
        """Drop the oldest *finished* jobs once history is full."""
        while len(self._jobs) > self.max_history:
            for job_id, job in list(self._jobs.items()):
                if job.status.is_terminal:
                    del self._jobs[job_id]
                    break
            else:
                return  # nothing terminal to evict; keep everything

    def shutdown(self, *, wait: bool = True) -> None:
        self._shutdown = True
        self._executor.shutdown(wait=wait)


#: Process-wide queue used by the API.  Created lazily so importing this module
#: never starts threads (which would break ``--help`` and test collection).
_default_queue: JobQueue | None = None
_default_lock = threading.Lock()


def get_queue(settings: Any | None = None) -> JobQueue:
    global _default_queue
    with _default_lock:
        if _default_queue is None:
            if settings is None:
                from app.core.config import get_settings

                settings = get_settings()
            _default_queue = JobQueue(
                concurrency=settings.workers.concurrency,
                default_max_retries=settings.workers.max_retries,
                retry_backoff_seconds=settings.workers.retry_backoff_seconds,
            )
        return _default_queue


def shutdown_queue() -> None:
    global _default_queue
    with _default_lock:
        if _default_queue is not None:
            _default_queue.shutdown(wait=False)
            _default_queue = None


__all__ = [
    "Job",
    "JobQueue",
    "available_jobs",
    "get_queue",
    "register_job",
    "shutdown_queue",
]
