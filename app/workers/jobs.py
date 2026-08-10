"""Registered background jobs.

Every job here is:

* **named** — submitted by a string, so an API request can never schedule an
  arbitrary callable;
* **idempotent where it can be** — re-running an ingest of the same file
  produces the same event ids and overwrites the same output files;
* **bounded** — each takes explicit limits rather than "process everything";
* **auditable** — results land in the metadata store, not only in memory.

Path arguments arriving from the API are resolved against the configured
ingest roots, so a job cannot be used to read outside them.
"""

from __future__ import annotations

import shutil
from datetime import timedelta
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.paths import resolve_within
from app.core.timeutil import parse_timestamp, utcnow
from app.workers.queue import register_job

log = get_logger(__name__)


@register_job("ingest")
def ingest_job(
    source: str,
    *,
    parser: str | None = None,
    service: str | None = None,
    layer: str = "processed",
    limit: int | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Ingest one file, directory or URL through the full pipeline."""
    from app.cache import build_cache, invalidate_after_ingest
    from app.pipeline import LogPipeline, PipelineOptions
    from app.storage import MetadataStore

    settings = get_settings()
    target = source
    if "://" not in source:
        # A path from an untrusted caller must stay inside the allowed roots.
        target = str(resolve_within(source, settings.ingest_roots(), must_exist=True))

    options = PipelineOptions(
        parser=parser, service=service, layer=layer, limit=limit, dry_run=dry_run
    )
    metadata = MetadataStore.from_settings(settings)
    metadata.create_schema()
    metadata.start_run(options.run_id, job_type="ingest", sources=[target])

    result = LogPipeline(settings).run(target, options)
    metadata.finish_run(result, error="; ".join(result.errors) or None)
    metadata.close()

    if result.records_written:
        invalidate_after_ingest(build_cache(settings.cache))
    return result.summary()


@register_job("ingest_directory")
def ingest_directory_job(
    directory: str, *, pattern: str = "*.log", workers: int | None = None
) -> dict[str, Any]:
    """Ingest every matching file in a directory, in parallel."""
    from app.core.paths import iter_files
    from app.pipeline import PipelineOptions, process_parallel

    settings = get_settings()
    root = resolve_within(directory, settings.ingest_roots(), must_exist=True)
    files = iter_files(root, (pattern,), follow_symlinks=settings.ingestion.follow_symlinks)
    if not files:
        return {"files": 0, "message": "no matching files"}
    result = process_parallel(files, settings, PipelineOptions(), workers=workers)
    return {"files": len(files), **result.summary()}


@register_job("report")
def report_job(
    *,
    start: str | None = None,
    end: str | None = None,
    kind: str = "summary",
    fmt: str = "json",
    hours: float = 24.0,
) -> dict[str, Any]:
    """Generate and persist a report."""
    from app.analytics.reports import ReportBuilder, save_report

    settings = get_settings()
    builder = ReportBuilder(settings)
    if kind == "daily":
        report = builder.daily(parse_timestamp(start))
    else:
        report = builder.build(
            parse_timestamp(start) or (utcnow() - timedelta(hours=hours)),
            parse_timestamp(end) or utcnow(),
        )
    path = save_report(report, settings.storage.data_root / "reports", fmt=fmt)
    return {
        "report": report.name,
        "path": str(path),
        "anomalies": len(report.anomalies),
        "security_findings": len(report.security_findings),
        "total_records": report.overview.total_records,
    }


@register_job("detect_anomalies")
def detect_anomalies_job(
    *, hours: float = 24.0, window: str = "5m", metrics: list[str] | None = None
) -> dict[str, Any]:
    """Scan the recent window for anomalies."""
    from app.anomaly_detection import DEFAULT_METRICS, AnomalyService

    settings = get_settings()
    end = utcnow()
    start = end - timedelta(hours=hours)
    anomalies = AnomalyService(settings=settings).scan(
        start, end, metrics=tuple(metrics or DEFAULT_METRICS), window=window
    )
    return {
        "window": window,
        "hours": hours,
        "anomalies": len(anomalies),
        "by_severity": _count_by(anomalies, "severity"),
        "top": [a.model_dump(mode="json") for a in anomalies[:10]],
    }


@register_job("security_scan")
def security_scan_job(*, hours: float = 24.0) -> dict[str, Any]:
    """Run the security detections over the recent window."""
    from app.analytics.security import SecurityAnalyzer

    settings = get_settings()
    end = utcnow()
    findings = SecurityAnalyzer(settings=settings).analyze(end - timedelta(hours=hours), end)
    return {
        "hours": hours,
        "findings": len(findings),
        "by_severity": _count_by(findings, "severity"),
        "top": [f.model_dump(mode="json") for f in findings[:10]],
    }


@register_job("cleanup")
def cleanup_job(
    *, retention_days: int = 90, layer: str = "raw", dry_run: bool = True
) -> dict[str, Any]:
    """Delete partitions older than the retention window.

    Defaults to ``dry_run=True``: a job that deletes data must be asked twice.
    Only whole partition directories under the platform's own data root are
    ever removed, and the path is re-checked before deletion.
    """
    from app.storage.partitioning import iter_partitions, partition_datetime

    settings = get_settings()
    roots = {
        "raw": settings.raw_path,
        "processed": settings.processed_path,
        "analytics": settings.analytics_path,
        "rejected": settings.rejected_path,
    }
    root = roots.get(layer)
    if root is None:
        raise ValueError(f"unknown layer {layer!r}; choose from {sorted(roots)}")

    cutoff = utcnow() - timedelta(days=retention_days)
    removed: list[str] = []
    freed = 0
    for partition in iter_partitions(root):
        moment = partition_datetime(partition)
        if moment is None or moment >= cutoff:
            continue
        # Belt and braces: never delete outside the configured data root.
        resolved = resolve_within(partition, [settings.storage.data_root])
        size = sum(f.stat().st_size for f in resolved.rglob("*") if f.is_file())
        removed.append(str(resolved))
        freed += size
        if not dry_run:
            shutil.rmtree(resolved, ignore_errors=False)

    log.info(
        "cleanup complete",
        extra={"layer": layer, "partitions": len(removed), "dry_run": dry_run},
    )
    return {
        "layer": layer,
        "retention_days": retention_days,
        "dry_run": dry_run,
        "partitions_removed": len(removed),
        "bytes_freed": freed,
        "partitions": removed[:50],
    }


@register_job("generate_data")
def generate_data_job(
    *, count: int = 100_000, fmt: str = "json", filename: str = "synthetic.log", seed: int = 1337
) -> dict[str, Any]:
    """Produce a synthetic dataset under the raw layer (demos, benchmarks)."""
    from app.core.paths import safe_filename
    from app.synthetic import generate_dataset

    settings = get_settings()
    target = settings.raw_path / safe_filename(filename, fallback="synthetic.log")
    path = generate_dataset(target, count=count, fmt=fmt, seed=seed)
    return {"path": str(path), "records": count, "bytes": path.stat().st_size}


@register_job("compact")
def compact_job(*, layer: str = "processed", target_mb: int = 128) -> dict[str, Any]:
    """Merge small Parquet files within each partition.

    Many small files are the classic cost of streaming ingestion: per-file
    metadata and open() calls come to dominate query time.  Compaction rewrites
    each partition into fewer, larger files, which is where Parquet's
    row-group statistics actually pay off.
    """
    import pyarrow.parquet as pq

    from app.core.paths import ensure_directory
    from app.storage.partitioning import iter_partitions

    settings = get_settings()
    root = settings.processed_path if layer == "processed" else settings.analytics_path
    compacted = 0
    reclaimed = 0

    for partition in iter_partitions(root):
        files = sorted(partition.glob("*.parquet"))
        if len(files) < 2:
            continue
        before = sum(f.stat().st_size for f in files)
        if before > target_mb * 1024**2 * len(files):
            continue
        table = pq.read_table(files)
        temp = partition / ".compacted.parquet.tmp"
        ensure_directory(partition)
        pq.write_table(table, temp, compression=settings.storage.compression)
        for file in files:
            file.unlink()
        temp.rename(partition / "part-compacted.parquet")
        after = (partition / "part-compacted.parquet").stat().st_size
        compacted += len(files)
        reclaimed += max(0, before - after)

    return {"layer": layer, "files_compacted": compacted, "bytes_reclaimed": reclaimed}


def _count_by(items: list[Any], attribute: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        key = str(getattr(item, attribute, "unknown"))
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


__all__ = [
    "cleanup_job",
    "compact_job",
    "detect_anomalies_job",
    "generate_data_job",
    "ingest_directory_job",
    "ingest_job",
    "report_job",
    "security_scan_job",
]
