#!/usr/bin/env python
"""Benchmark the platform end to end and compare analytical engines.

What it measures
----------------
1. **Generation** — synthetic dataset throughput (the control).
2. **Ingestion**  — full pipeline: parse → clean → normalise → enrich →
   validate → deduplicate → write Parquet, in records/s, MB/s and peak RSS.
3. **Stage split** — the same records through each stage individually, so a
   regression can be attributed instead of guessed at.
4. **Query engines** — the same aggregation in DuckDB (over Parquet), Polars
   and pandas, to show where each wins.

Methodology
-----------
* Every run uses the same seeded dataset, so numbers are comparable across
  machines and commits.
* Memory is sampled before and after with RSS; it is a floor, not a peak, and
  is reported as such.
* Each engine query runs once after a warm-up read, on a cold DuckDB
  connection, so no result is served from a query cache.

Usage
-----
    python benchmarks/benchmark.py --records 1000000
    python benchmarks/benchmark.py --records 100000 --output results/run.json
"""

from __future__ import annotations

import argparse
import gc
import json
import platform
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import load_settings  # noqa: E402
from app.core.metrics import memory_usage_mb  # noqa: E402
from app.pipeline import LogPipeline, PipelineOptions  # noqa: E402
from app.synthetic import generate_dataset  # noqa: E402


@dataclass
class Measurement:
    name: str
    seconds: float
    records: int = 0
    bytes_processed: int = 0
    memory_delta_mb: float = 0.0
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def records_per_second(self) -> float:
        return self.records / self.seconds if self.seconds > 0 else 0.0

    @property
    def megabytes_per_second(self) -> float:
        return (self.bytes_processed / 1024**2) / self.seconds if self.seconds > 0 else 0.0

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["records_per_second"] = round(self.records_per_second, 1)
        payload["megabytes_per_second"] = round(self.megabytes_per_second, 3)
        payload["seconds"] = round(self.seconds, 4)
        payload["memory_delta_mb"] = round(self.memory_delta_mb, 1)
        return payload


class Timer:
    """Times a block and records the RSS delta around it."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.measurement = Measurement(name=name, seconds=0.0)

    def __enter__(self) -> Measurement:
        gc.collect()
        self._memory_before = memory_usage_mb()
        self._started = time.perf_counter()
        return self.measurement

    def __exit__(self, *exc: object) -> None:
        self.measurement.seconds = time.perf_counter() - self._started
        gc.collect()
        self.measurement.memory_delta_mb = memory_usage_mb() - self._memory_before


def environment() -> dict[str, Any]:
    import os

    info: dict[str, Any] = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "cpu_count": os.cpu_count(),
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    try:
        import psutil

        info["total_memory_gb"] = round(psutil.virtual_memory().total / 1024**3, 1)
    except ImportError:
        pass
    for module in ("duckdb", "pyarrow", "polars", "pandas", "pydantic"):
        try:
            info[module] = __import__(module).__version__
        except Exception:  # noqa: BLE001 - an absent optional engine is fine
            info[module] = None
    return info


def benchmark_generation(path: Path, records: int, fmt: str) -> Measurement:
    with Timer(f"generate::{fmt}") as measurement:
        generate_dataset(path, count=records, fmt=fmt, seed=1337)
    measurement.records = records
    measurement.bytes_processed = path.stat().st_size
    measurement.detail = {"format": fmt, "file_mb": round(path.stat().st_size / 1024**2, 2)}
    return measurement


def benchmark_ingestion(source: Path, data_root: Path, workers: int) -> Measurement:
    settings = load_settings(
        overrides={
            "environment": "test",
            "storage": {"data_root": str(data_root), "write_batch_size": 50_000},
            "ingestion": {"allowed_roots": [str(source.parent)]},
            "processing": {"workers": workers},
            "observability": {"level": "ERROR", "format": "console"},
        }
    )
    with Timer("ingest::full_pipeline") as measurement:
        result = LogPipeline(settings).run(source, PipelineOptions(run_id="bench"))
    measurement.records = result.records_written
    measurement.bytes_processed = result.bytes_read
    measurement.detail = {
        "lines_read": result.lines_read,
        "rejected": result.records_rejected,
        "duplicates": result.records_duplicate,
        "output_files": len(result.outputs),
        "parquet_mb": round(
            sum(f.stat().st_size for f in data_root.rglob("*.parquet")) / 1024**2, 2
        ),
    }
    return measurement


def benchmark_stages(source: Path, limit: int) -> list[Measurement]:
    """Time each pipeline stage over the same records, in isolation."""
    from app.deduplication import Deduplicator
    from app.parsers import ParseContext, detect_format, get_parser
    from app.transformation.cleaning import RecordCleaner
    from app.transformation.enrichment import RecordEnricher
    from app.transformation.normalization import RecordNormalizer
    from app.validation import RecordValidator

    lines = []
    with source.open("r", encoding="utf-8", errors="replace") as stream:
        for index, line in enumerate(stream):
            if index >= limit:
                break
            if line.strip():
                lines.append(line.rstrip("\n"))

    parser = get_parser(detect_format(lines[:25], filename=source.name).parser_name)
    context = ParseContext(source=str(source))
    measurements: list[Measurement] = []

    with Timer("stage::parse") as measurement:
        events = []
        for line in lines:
            try:
                events.append(parser.parse(line, context))
            except Exception:  # noqa: BLE001,S112 - rejections are the point
                continue
    measurement.records = len(events)
    measurements.append(measurement)

    cleaner = RecordCleaner()
    with Timer("stage::clean") as measurement:
        cleaned = [cleaner.clean(event) for event in events]
    measurement.records = len(cleaned)
    measurements.append(measurement)

    normalizer = RecordNormalizer()
    with Timer("stage::normalise") as measurement:
        normalised = [normalizer.normalise(event) for event in cleaned]
    measurement.records = len(normalised)
    measurements.append(measurement)

    enricher = RecordEnricher()
    with Timer("stage::enrich") as measurement:
        enriched = [enricher.enrich(event) for event in normalised]
    measurement.records = len(enriched)
    measurements.append(measurement)

    validator = RecordValidator()
    with Timer("stage::validate") as measurement:
        outcomes = [validator.validate(event) for event in enriched]
    measurement.records = len(outcomes)
    measurements.append(measurement)

    deduplicator = Deduplicator()
    with Timer("stage::deduplicate") as measurement:
        unique = [e for e in enriched if not deduplicator.is_duplicate(e)]
    measurement.records = len(enriched)
    measurement.detail = {"unique": len(unique)}
    measurements.append(measurement)

    return measurements


def benchmark_engines(data_root: Path) -> list[Measurement]:
    """Run the same aggregation on DuckDB, Polars and pandas."""
    measurements: list[Measurement] = []
    files = sorted(data_root.rglob("*.parquet"))
    if not files:
        return measurements
    globs = [str(path) for path in files]
    total_bytes = sum(path.stat().st_size for path in files)

    # --- DuckDB: streams from Parquet, no materialisation ------------------- #
    try:
        import duckdb

        connection = duckdb.connect(":memory:")
        connection.execute("SET TimeZone='UTC'")
        quoted = ", ".join(f"'{g}'" for g in globs)
        query = (
            "SELECT service, COUNT(*) AS n, "  # noqa: S608 - local file list, not input
            "COUNT(*) FILTER (WHERE level IN ('ERROR','CRITICAL')) AS errors, "
            "approx_quantile(response_time_ms, 0.95) AS p95 "
            f"FROM read_parquet([{quoted}]) GROUP BY 1 ORDER BY 2 DESC"
        )
        connection.execute(query).fetchall()  # warm-up
        with Timer("query::duckdb") as measurement:
            rows = connection.execute(query).fetchall()
        measurement.records = sum(int(row[1]) for row in rows)
        measurement.bytes_processed = total_bytes
        measurement.detail = {"groups": len(rows)}
        measurements.append(measurement)
        connection.close()
    except ImportError:
        pass

    # --- Polars: reads into an Arrow-backed frame --------------------------- #
    try:
        import polars as pl

        with Timer("query::polars") as measurement:
            frame = pl.read_parquet(globs)
            result = (
                frame.group_by("service")
                .agg(
                    pl.len().alias("n"),
                    pl.col("level").is_in(["ERROR", "CRITICAL"]).sum().alias("errors"),
                    pl.col("response_time_ms").quantile(0.95).alias("p95"),
                )
                .sort("n", descending=True)
            )
        measurement.records = int(frame.height)
        measurement.bytes_processed = total_bytes
        measurement.detail = {"groups": int(result.height)}
        measurements.append(measurement)
    except ImportError:
        pass

    # --- pandas: the baseline everyone knows -------------------------------- #
    try:
        import pandas as pd

        with Timer("query::pandas") as measurement:
            frame = pd.concat([pd.read_parquet(path) for path in files], ignore_index=True)
            grouped = frame.groupby("service").agg(
                n=("event_id", "count"),
                errors=("level", lambda s: s.isin(["ERROR", "CRITICAL"]).sum()),
                p95=("response_time_ms", lambda s: s.quantile(0.95)),
            )
        measurement.records = int(len(frame))
        measurement.bytes_processed = total_bytes
        measurement.detail = {"groups": int(len(grouped))}
        measurements.append(measurement)
    except ImportError:
        pass

    return measurements


def benchmark_analytics(data_root: Path) -> list[Measurement]:
    """Time the platform's own analytics views."""
    from app.analytics import AnalyticsEngine
    from app.anomaly_detection import AnomalyService

    settings = load_settings(
        overrides={
            "environment": "test",
            "storage": {"data_root": str(data_root.parent)},
            "observability": {"level": "ERROR", "format": "console"},
        }
    )
    engine = AnalyticsEngine(settings=settings)
    measurements: list[Measurement] = []

    for name, call in (
        ("analytics::overview", lambda: engine.overview()),
        ("analytics::errors", lambda: engine.errors()),
        ("analytics::latency", lambda: engine.latency()),
        ("analytics::traffic", lambda: engine.traffic()),
        ("analytics::services", lambda: engine.services()),
        ("analytics::timeseries_5m", lambda: engine.timeseries("requests", window="5m")),
        (
            "analytics::anomaly_scan",
            lambda: AnomalyService(engine, settings).scan(window="15m"),
        ),
    ):
        with Timer(name) as measurement:
            call()
        measurements.append(measurement)
    engine.close()
    return measurements


def render(results: dict[str, Any]) -> str:
    """Human-readable summary table."""
    lines = [
        "",
        "=" * 78,
        " Big Data Log Analytics Platform - benchmark",
        "=" * 78,
        f" python {results['environment']['python']} on {results['environment']['platform']}",
        f" cpus: {results['environment']['cpu_count']}"
        f"   memory: {results['environment'].get('total_memory_gb', '?')} GB",
        "-" * 78,
        f" {'measurement':<30}{'seconds':>10}{'records/s':>14}{'MB/s':>10}{'RSS MB':>12}",
        "-" * 78,
    ]
    for measurement in results["measurements"]:
        lines.append(
            f" {measurement['name']:<30}"
            f"{measurement['seconds']:>10.3f}"
            f"{measurement['records_per_second']:>14,.0f}"
            f"{measurement['megabytes_per_second']:>10.2f}"
            f"{measurement['memory_delta_mb']:>12.1f}"
        )
    lines += ["-" * 78, ""]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=int, default=100_000)
    parser.add_argument("--format", default="json", choices=["json", "access", "plaintext", "csv"])
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--stage-sample", type=int, default=20_000)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--skip-engines", action="store_true")
    args = parser.parse_args()

    measurements: list[Measurement] = []
    with TemporaryDirectory(prefix="loga-bench-") as tmp:
        workspace = Path(tmp)
        source = workspace / "raw" / f"bench.{'csv' if args.format == 'csv' else 'log'}"
        data_root = workspace / "data"

        print(f"generating {args.records:,} records ({args.format}) ...")
        measurements.append(benchmark_generation(source, args.records, args.format))

        print("ingesting ...")
        measurements.append(benchmark_ingestion(source, data_root, args.workers))

        print("timing individual stages ...")
        measurements.extend(benchmark_stages(source, min(args.stage_sample, args.records)))

        processed = data_root / "processed"
        if not args.skip_engines:
            print("comparing query engines ...")
            measurements.extend(benchmark_engines(processed))

        print("timing analytics views ...")
        measurements.extend(benchmark_analytics(processed))

    ingest = next(m for m in measurements if m.name == "ingest::full_pipeline")
    results = {
        "environment": environment(),
        "parameters": {
            "records": args.records,
            "format": args.format,
            "workers": args.workers,
        },
        "summary": {
            "ingest_records_per_second": round(ingest.records_per_second, 1),
            "ingest_megabytes_per_second": round(ingest.megabytes_per_second, 3),
            "ingest_seconds": round(ingest.seconds, 3),
            "compression_ratio": round(
                (ingest.bytes_processed / 1024**2) / max(ingest.detail["parquet_mb"], 0.001), 2
            ),
        },
        "measurements": [m.as_dict() for m in measurements],
    }

    print(render(results))
    print(
        f" Parquet compression: {results['summary']['compression_ratio']}x "
        f"({ingest.detail['parquet_mb']} MB from "
        f"{ingest.bytes_processed / 1024**2:.1f} MB of raw text)\n"
    )

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f" results written to {args.output}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
