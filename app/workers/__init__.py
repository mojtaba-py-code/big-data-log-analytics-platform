"""Background processing layer.

Importing this package registers every job, so ``available_jobs()`` is
populated before the API or CLI needs it.
"""

from __future__ import annotations

from app.workers import jobs  # noqa: F401 - imported for job registration
from app.workers.queue import (
    Job,
    JobQueue,
    available_jobs,
    get_queue,
    register_job,
    shutdown_queue,
)

__all__ = [
    "Job",
    "JobQueue",
    "available_jobs",
    "get_queue",
    "register_job",
    "shutdown_queue",
]
