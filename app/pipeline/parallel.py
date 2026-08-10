"""Parallel batch processing.

Why processes, not threads
--------------------------
Parsing is CPU-bound (regex, JSON decoding, Pydantic validation) and therefore
serialised by the GIL.  Threads would add contention without adding throughput.
Processes give real parallelism at the cost of one Python interpreter per
worker (~40 MB) and pickling overhead at the boundary.

Unit of parallelism: the file
-----------------------------
Each worker owns whole files.  Splitting a single file across workers would
require byte-offset seeking, line-boundary reconciliation and shared
deduplication state — a lot of complexity for a case that only matters when
one file dwarfs all the others.  With one file per worker:

* no shared mutable state, so no locks;
* each worker writes its own Parquet files (named per worker), so no write
  contention;
* a crashed worker loses one file's progress, not the run's.

The deduplication trade-off
---------------------------
Per-worker dedup state means duplicates *spanning two files* are not detected
in a parallel run.  This is documented rather than hidden: use ``--workers 1``
when cross-file exactness matters, or run the ``event_id`` strategy and let the
deterministic ids collapse duplicates at query time.

Sizing
------
Default ``workers = min(configured, cpu_count - 1, file_count)``, never above
the file count, and never all cores — leaving one free keeps the machine
responsive, which matters on the 2-core laptops this also has to run on.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import replace
from pathlib import Path

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.timeutil import utcnow
from app.models.results import PipelineResult
from app.pipeline.orchestrator import LogPipeline, PipelineOptions

log = get_logger(__name__)


def effective_worker_count(requested: int, item_count: int) -> int:
    """Never more workers than there is work, never every core."""
    cpu = os.cpu_count() or 2
    return max(1, min(requested, item_count, max(1, cpu - 1)))


def _run_one(target: str, settings: Settings, options: PipelineOptions) -> PipelineResult:
    """Worker entry point — must be a module-level function to be picklable."""
    from app.core.logging import configure_from_settings

    configure_from_settings(settings)
    return LogPipeline(settings).run(target, options)


def process_parallel(
    targets: Sequence[str | Path],
    settings: Settings | None = None,
    options: PipelineOptions | None = None,
    *,
    workers: int | None = None,
) -> PipelineResult:
    """Process many files concurrently and merge the results.

    A worker failure is recorded on the combined result and the remaining
    workers continue — losing one file must not lose the whole job.
    """
    config = settings or get_settings()
    opts = options or PipelineOptions()
    paths = [str(t) for t in targets]
    if not paths:
        return PipelineResult(run_id=opts.run_id, finished_at=utcnow())

    count = effective_worker_count(workers or config.processing.workers, len(paths))
    combined = PipelineResult(run_id=opts.run_id)

    if count == 1:
        pipeline = LogPipeline(config)
        for index, path in enumerate(paths):
            combined.merge(pipeline.run(path, replace(opts, run_id=f"{opts.run_id}-{index:03d}")))
        combined.finished_at = utcnow()
        return combined

    log.info("starting parallel run", extra={"workers": count, "files": len(paths)})
    with ProcessPoolExecutor(max_workers=count) as pool:
        futures = {
            pool.submit(
                _run_one, path, config, replace(opts, run_id=f"{opts.run_id}-{index:03d}")
            ): path
            for index, path in enumerate(paths)
        }
        for future in as_completed(futures):
            path = futures[future]
            try:
                combined.merge(future.result())
            except Exception as exc:  # noqa: BLE001 - isolate worker failures
                combined.succeeded = False
                combined.errors.append(f"{Path(path).name}: {type(exc).__name__}: {exc}")
                log.error(
                    "worker failed",
                    extra={"file": path, "error_type": type(exc).__name__},
                )

    combined.finished_at = utcnow()
    combined.sources = paths
    log.info("parallel run finished", extra=combined.summary())
    return combined


__all__ = ["effective_worker_count", "process_parallel"]
