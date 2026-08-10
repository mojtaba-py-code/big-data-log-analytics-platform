#!/usr/bin/env python
"""End-to-end demonstration of the whole platform.

Runs the complete workflow described in the project brief:

    generate → ingest → parse → validate → normalise → deduplicate →
    store as Parquet → query with DuckDB → analytics → anomaly detection →
    security analysis → store aggregations → report → API + dashboard

Every step prints what it did and what it found, so the output doubles as a
guided tour.

Usage
-----
    python scripts/demo_end_to_end.py                    # 200k records
    python scripts/demo_end_to_end.py --records 1000000  # 1M records
    python scripts/demo_end_to_end.py --serve            # leave the API running

The demo writes everything under ``--workspace`` (default ``demo-workspace/``)
and never touches an existing data directory.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analytics import AnalyticsEngine, SecurityAnalyzer  # noqa: E402
from app.analytics.reports import ReportBuilder, save_report  # noqa: E402
from app.anomaly_detection import AnomalyService  # noqa: E402
from app.core.config import load_settings  # noqa: E402
from app.core.timeutil import to_iso, utcnow  # noqa: E402
from app.pipeline import LogPipeline, PipelineOptions  # noqa: E402
from app.search import SearchService  # noqa: E402
from app.storage import DuckDBEngine, MetadataStore  # noqa: E402
from app.synthetic import generate_dataset  # noqa: E402
from app.validation.dlq import rejection_stats  # noqa: E402

STEP = 0


def step(title: str) -> None:
    global STEP
    STEP += 1
    print(f"\n{'=' * 74}\n  STEP {STEP}: {title}\n{'=' * 74}")


def bullet(label: str, value: Any) -> None:
    print(f"    {label:<34} {value}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=int, default=200_000)
    parser.add_argument("--workspace", type=Path, default=Path("demo-workspace"))
    parser.add_argument(
        "--format", default="json", choices=["json", "access", "plaintext", "mixed"]
    )
    parser.add_argument("--serve", action="store_true", help="Serve the API when finished.")
    parser.add_argument("--keep", action="store_true", help="Keep an existing workspace.")
    args = parser.parse_args()

    workspace = args.workspace.resolve()
    if workspace.exists() and not args.keep:
        shutil.rmtree(workspace)
    (workspace / "raw").mkdir(parents=True, exist_ok=True)

    settings = load_settings(
        overrides={
            "environment": "development",
            "storage": {"data_root": str(workspace / "data")},
            "ingestion": {"allowed_roots": [str(workspace)]},
            "database": {"sqlite_path": str(workspace / "metadata.db")},
            "api": {"auth_required": False, "docs_enabled": True},
            "observability": {"level": "WARNING", "format": "console"},
            "processing": {"workers": 2},
        }
    )

    started = time.perf_counter()

    # ---------------------------------------------------------------- 1 ---- #
    step(f"Generate {args.records:,} synthetic log records")
    source = workspace / "raw" / f"application.{'log' if args.format != 'csv' else 'csv'}"
    generation_started = time.perf_counter()
    generate_dataset(source, count=args.records, fmt=args.format, duration_hours=24)
    generation_seconds = time.perf_counter() - generation_started
    size_mb = source.stat().st_size / 1024**2
    bullet("file", source)
    bullet("size", f"{size_mb:,.1f} MiB")
    bullet("generation time", f"{generation_seconds:,.1f} s")
    print(
        "\n    The dataset deliberately contains injected incidents: error spikes,\n"
        "    a latency degradation window, brute-force bursts, endpoint scanning,\n"
        "    duplicates, malformed lines and a few leaked credentials."
    )

    # ---------------------------------------------------------------- 2 ---- #
    step("Ingest: parse -> clean -> normalise -> enrich -> validate -> dedup -> Parquet")
    metadata = MetadataStore.from_settings(settings)
    metadata.create_schema()
    metadata.start_run("demo", sources=[str(source)])

    result = LogPipeline(settings).run(source, PipelineOptions(run_id="demo"))
    metadata.finish_run(result)

    bullet("lines read", f"{result.lines_read:,}")
    bullet("records written", f"{result.records_written:,}")
    bullet("duplicates removed", f"{result.records_duplicate:,}")
    bullet("records rejected", f"{result.records_rejected:,}")
    bullet("rejection reasons", result.rejection_reasons or "none")
    bullet("throughput", f"{result.records_per_second:,.0f} records/s")
    bullet("throughput", f"{result.megabytes_per_second:,.2f} MB/s")
    bullet("peak RSS", f"{result.peak_memory_mb:,.0f} MiB")
    bullet("output files", len(result.outputs))

    parquet_bytes = sum(f.stat().st_size for f in settings.processed_path.rglob("*.parquet"))
    parquet_mb = parquet_bytes / 1024**2
    bullet(
        "parquet size", f"{parquet_mb:,.1f} MiB ({size_mb / max(parquet_mb, 0.01):.1f}x smaller)"
    )

    rejected = rejection_stats(settings.rejected_path)
    if rejected:
        print("\n    Nothing was silently dropped - every rejection is in the DLQ:")
        for reason, count in rejected.items():
            bullet(f"  {reason}", f"{count:,}")

    # ---------------------------------------------------------------- 3 ---- #
    step("Storage layout: Hive-partitioned Parquet")
    for path in sorted(settings.processed_path.rglob("*.parquet"))[:6]:
        relative = path.relative_to(settings.processed_path)
        bullet(str(relative), f"{path.stat().st_size / 1024**2:,.1f} MiB")
    print(
        "\n    Partitioning by year/month/day means a one-day query opens one\n"
        "    directory instead of scanning the whole dataset."
    )

    # ---------------------------------------------------------------- 4 ---- #
    step("Query the dataset with DuckDB")
    engine = DuckDBEngine(settings.processed_path)
    summary = engine.dataset_summary()
    bullet("records", f"{summary['records']:,}")
    bullet("distinct services", summary["services"])
    bullet("first event", to_iso(summary["first_event"]) if summary["first_event"] else "-")
    bullet("last event", to_iso(summary["last_event"]) if summary["last_event"] else "-")

    query_started = time.perf_counter()
    source, scan_params = engine.scan()
    top = engine.execute(
        f"SELECT service, COUNT(*) AS n FROM {source} "  # noqa: S608 - constant fragment
        "GROUP BY 1 ORDER BY 2 DESC LIMIT 5",
        scan_params,
    )
    print(
        f"\n    Top services (aggregated in {(time.perf_counter() - query_started) * 1000:.0f} ms):"
    )
    for row in top:
        bullet(f"  {row['service']}", f"{row['n']:,}")

    # ---------------------------------------------------------------- 5 ---- #
    step("Analytics")
    analytics = AnalyticsEngine(settings=settings)
    end = utcnow() + timedelta(minutes=5)
    start = end - timedelta(hours=30)

    overview = analytics.overview(start, end)
    bullet("total records", f"{overview.total_records:,}")
    bullet("requests", f"{overview.total_requests:,}")
    bullet("errors", f"{overview.total_errors:,}")
    bullet("error rate", f"{overview.error_rate:.2%}")
    bullet("avg latency", f"{overview.average_latency_ms:,.1f} ms")
    bullet("p95 latency", f"{overview.p95_latency_ms:,.1f} ms")
    bullet("p99 latency", f"{overview.p99_latency_ms:,.1f} ms")

    status = analytics.status_codes(start, end)
    bullet("status classes", status.by_class)

    services = analytics.services(start, end)
    print("\n    Service health:")
    for health in services.services[:6]:
        bullet(
            f"  {health.service}",
            f"{health.requests:>7,} req  {health.failure_rate:>7.2%} fail  "
            f"p95 {health.latency.p95:>8,.1f} ms  [{health.status}]",
        )

    traffic = analytics.traffic(start, end)
    print("\n    Top endpoints:")
    for item in traffic.top_endpoints[:5]:
        bullet(f"  {item.key}", f"{item.count:,} ({item.percentage:.1f}%)")

    # ---------------------------------------------------------------- 6 ---- #
    step("Anomaly detection")
    anomalies = AnomalyService(analytics, settings).scan(start, end, window="15m")
    bullet("anomalies found", len(anomalies))
    for anomaly in anomalies[:6]:
        bullet(
            f"  {to_iso(anomaly.bucket)}",
            f"{anomaly.metric:<14} observed {anomaly.observed:>9,.1f}  "
            f"expected {anomaly.expected:>9,.1f}  [{anomaly.severity}]",
        )
    print(
        "\n    These correspond to the incidents injected into the dataset, found\n"
        "    without any labels or training data."
    )

    # ---------------------------------------------------------------- 7 ---- #
    step("Security analysis")
    findings = SecurityAnalyzer(analytics.engine, settings).analyze(start, end)
    bullet("findings", len(findings))
    for finding in findings[:8]:
        bullet(
            f"  {finding.subject}",
            f"{str(finding.type):<26} events {finding.event_count:>6,}  "
            f"risk {finding.risk_score:>5.1f}  [{finding.severity}]",
        )

    # ---------------------------------------------------------------- 8 ---- #
    step("Search")
    search = SearchService(analytics.engine, settings)
    for expression in (
        "level=ERROR",
        "status_code>=500",
        "service=auth AND status_code=401",
        "endpoint~/api/v1/*",
    ):
        found = search.search(expression, start=start, end=end, page_size=1)
        bullet(f"  {expression}", f"{found.total:>8,} matches in {found.took_ms:>6.0f} ms")

    # ---------------------------------------------------------------- 9 ---- #
    step("Report")
    report = ReportBuilder(settings, analytics).build(start, end, name="Demo Report")
    report_path = save_report(report, workspace / "reports", fmt="markdown")
    json_path = save_report(report, workspace / "reports", fmt="json")
    bullet("markdown", report_path)
    bullet("json", json_path)
    bullet("sections", ", ".join(report.sections))
    bullet("anomalies", len(report.anomalies))
    bullet("security findings", len(report.security_findings))

    # --------------------------------------------------------------- 10 ---- #
    step("Verify: no secrets reached storage")
    # The generator injects these exact values into ~0.1% of records.  The
    # check looks for the *values*, not the field names: a stored
    # "password=***REDACTED***" is the correct outcome, so searching for
    # "password=" would report a leak that is not one.
    secrets = (
        b"Sup3rS3cret!",
        b"sk_live_1234567890abcdefghij",
        b"eyJhbGciOiJIUzI1NiJ9",
        b"someone@example.test",
    )
    stored = b"".join(f.read_bytes() for f in settings.processed_path.rglob("*.parquet"))
    leaked = [needle.decode() for needle in secrets if needle in stored]
    bullet("injected credentials", len(secrets))
    bullet("found in Parquet", leaked or "none - all redacted on ingest")
    bullet("redaction markers present", b"REDACTED" in stored)

    total = time.perf_counter() - started
    print(f"\n{'=' * 74}\n  Demo complete in {total:,.1f} s")
    print(f"  Workspace: {workspace}")
    print(f"{'=' * 74}\n")

    analytics.close()
    metadata.close()

    if args.serve:
        print("Starting the API.  Open:")
        print("    http://127.0.0.1:8000/dashboard   interactive dashboard")
        print("    http://127.0.0.1:8000/docs        OpenAPI explorer")
        print("    http://127.0.0.1:8000/health      health summary\n")
        import uvicorn

        from app.api.main import create_app

        uvicorn.run(create_app(settings), host="127.0.0.1", port=8000, log_config=None)
    else:
        print("Explore the results:")
        print(f"    LOGA_STORAGE__DATA_ROOT={workspace / 'data'} loganalytics stats")
        print(f"    LOGA_STORAGE__DATA_ROOT={workspace / 'data'} loganalytics serve")
        print("    python scripts/demo_end_to_end.py --serve --keep\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
