"""Background job endpoints.

Jobs are submitted **by name** from a registry, never as arbitrary callables or
module paths, so a request cannot schedule code that the platform did not ship.
Every submission requires the ``write`` scope; destructive jobs require
``admin``.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import get_job_queue
from app.api.security import Principal, RequireRead, require_scope
from app.core.logging import get_logger
from app.models.enums import JobStatus
from app.workers.queue import JobQueue, available_jobs

log = get_logger(__name__)

router = APIRouter(prefix="/jobs", tags=["jobs"])

#: Jobs that delete or rewrite data need the highest privilege.
_ADMIN_JOBS = frozenset({"cleanup", "compact"})


class JobSubmission(BaseModel):
    """Request body for ``POST /jobs``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(max_length=64, description="A registered job name.")
    parameters: dict[str, Any] = Field(
        default_factory=dict, description="Keyword arguments for the job."
    )
    max_retries: int | None = Field(default=None, ge=0, le=10)


@router.get("", summary="List jobs", dependencies=[RequireRead])
async def list_jobs(
    queue: Annotated[JobQueue, Depends(get_job_queue)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    job_status: Annotated[JobStatus | None, Query(alias="status")] = None,
) -> dict[str, Any]:
    """Recent jobs, newest first."""
    jobs = queue.list(limit=limit, status=job_status)
    return {"jobs": [job.as_dict() for job in jobs], "stats": queue.stats()}


@router.get("/available", summary="List submittable jobs", dependencies=[RequireRead])
async def list_available() -> dict[str, Any]:
    return {"jobs": available_jobs(), "admin_only": sorted(_ADMIN_JOBS)}


@router.post("", summary="Submit a job", status_code=status.HTTP_202_ACCEPTED)
async def submit_job(
    queue: Annotated[JobQueue, Depends(get_job_queue)],
    principal: Annotated[Principal, Depends(require_scope("write"))],
    submission: Annotated[JobSubmission, Body()],
) -> dict[str, Any]:
    """Queue a job for background execution."""
    if submission.name not in available_jobs():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown job; available: {', '.join(available_jobs())}",
        )
    if submission.name in _ADMIN_JOBS and not principal.has("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"the '{submission.name}' job requires the 'admin' scope",
        )

    job = queue.submit(submission.name, max_retries=submission.max_retries, **submission.parameters)
    log.info(
        "job submitted via API",
        extra={"job": submission.name, "job_id": job.id, "principal": principal.name},
    )
    return {"job": job.as_dict(), "status_url": f"/jobs/{job.id}"}


@router.get("/{job_id}", summary="Job status", dependencies=[RequireRead])
async def get_job(
    queue: Annotated[JobQueue, Depends(get_job_queue)],
    job_id: Annotated[str, Path(min_length=4, max_length=64, pattern="^[a-f0-9]+$")],
) -> dict[str, Any]:
    job = queue.get(job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="job not found")
    return job.as_dict()


@router.delete("/{job_id}", summary="Cancel a queued job")
async def cancel_job(
    queue: Annotated[JobQueue, Depends(get_job_queue)],
    job_id: Annotated[str, Path(min_length=4, max_length=64, pattern="^[a-f0-9]+$")],
    _: Annotated[Principal, Depends(require_scope("write"))],
) -> dict[str, Any]:
    """Cancel a job that has not started.

    Running jobs cannot be cancelled: interrupting a writer mid-flush would
    leave a partial output file behind.
    """
    if not queue.cancel(job_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="the job is already running or finished and cannot be cancelled",
        )
    return {"cancelled": job_id}


__all__ = ["router"]
