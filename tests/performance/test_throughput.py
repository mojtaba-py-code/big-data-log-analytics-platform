"""Performance and memory tests.

These assert *properties*, not absolute numbers: a wall-clock threshold would
fail on a slow CI runner and pass on a fast laptop while hiding a real
regression.  What is asserted instead:

* memory stays flat as input size grows (the streaming guarantee);
* throughput does not collapse between sizes (no accidental O(n²));
* the storage layer's memory is governed by batch size, not dataset size.

The absolute measurements live in ``benchmarks/`` and in ``docs/PERFORMANCE.md``.

Run with ``pytest -m performance``; they are excluded from the default run.
"""

from __future__ import annotations

import gc
import json
import time
from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.metrics import memory_usage_mb
from app.pipeline import LogPipeline, PipelineOptions
from app.synthetic import generate_dataset

pytestmark = [pytest.mark.performance, pytest.mark.slow]


def _write_log(path: Path, count: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        for index in range(count):
            stream.write(
                json.dumps(
                    {
                        "timestamp": f"2026-08-07T12:{index % 60:02d}:{index % 60:02d}Z",
                        "level": "ERROR" if index % 5 == 0 else "INFO",
                        "service": f"svc-{index % 8}",
                        "message": f"record {index}",
                        "http": {
                            "status": 500 if index % 5 == 0 else 200,
                            "duration_ms": float(index % 500),
                            "path": f"/api/v1/x/{index % 100}",
                        },
                        "client_ip": f"192.0.2.{index % 250 + 1}",
                    }
                )
                + "\n"
            )
    return path


class TestStreamingMemory:
    def test_memory_is_flat_across_input_sizes(self, settings: Settings, tmp_path: Path) -> None:
        """10x the input must not mean 10x the resident memory."""
        measurements: dict[int, float] = {}
        for count in (5_000, 50_000):
            gc.collect()
            before = memory_usage_mb()
            path = _write_log(tmp_path / "raw" / f"n{count}.log", count)
            result = LogPipeline(settings).run(path, PipelineOptions(run_id=f"p{count}"))
            assert result.records_written == count
            gc.collect()
            measurements[count] = memory_usage_mb() - before

        growth = measurements[50_000] - measurements[5_000]
        # A streaming pipeline should add at most tens of MB for 10x the data.
        assert growth < 150, f"memory grew by {growth:.1f} MB for 10x the input"

    def test_source_iteration_does_not_materialise(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        from app.ingestion import FileSource

        path = _write_log(tmp_path / "raw" / "stream.log", 100_000)
        gc.collect()
        before = memory_usage_mb()
        consumed = sum(1 for _ in FileSource(path).read())
        gc.collect()
        assert consumed == 100_000
        assert memory_usage_mb() - before < 80


class TestThroughput:
    def test_throughput_does_not_degrade_with_size(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        """Rates must stay within a constant factor — no quadratic behaviour."""
        rates: dict[int, float] = {}
        for count in (10_000, 50_000):
            path = _write_log(tmp_path / "raw" / f"t{count}.log", count)
            started = time.perf_counter()
            result = LogPipeline(settings).run(path, PipelineOptions(run_id=f"t{count}"))
            elapsed = time.perf_counter() - started
            rates[count] = result.records_written / elapsed

        assert rates[50_000] > rates[10_000] * 0.5, f"throughput collapsed: {rates}"

    def test_reports_throughput_metrics(self, settings: Settings, tmp_path: Path) -> None:
        path = _write_log(tmp_path / "raw" / "metrics.log", 20_000)
        result = LogPipeline(settings).run(path, PipelineOptions(run_id="m"))
        assert result.records_per_second > 0
        assert result.megabytes_per_second > 0
        assert result.peak_memory_mb > 0


class TestQueryPerformance:
    def test_partition_pruning_beats_a_full_scan(self, settings: Settings, tmp_path: Path) -> None:
        """A narrow window must not read the whole dataset."""
        from datetime import UTC, datetime, timedelta

        from app.storage import DuckDBEngine
        from app.storage.partitioning import glob_for_range

        path = tmp_path / "raw" / "wide.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as stream:
            base = datetime(2026, 6, 1, tzinfo=UTC)
            for day in range(60):
                for index in range(200):
                    moment = base + timedelta(days=day, seconds=index)
                    stream.write(
                        json.dumps({"timestamp": moment.isoformat(), "message": f"d{day}-{index}"})
                        + "\n"
                    )
        LogPipeline(settings).run(path, PipelineOptions(run_id="wide"))

        all_globs = glob_for_range(settings.processed_path)
        one_day = glob_for_range(
            settings.processed_path,
            datetime(2026, 6, 10, tzinfo=UTC),
            datetime(2026, 6, 10, 23, 59, tzinfo=UTC),
        )
        assert len(one_day) == 1
        assert len(all_globs) >= 55

        engine = DuckDBEngine(settings.processed_path)
        assert (
            engine.count_logs(
                start=datetime(2026, 6, 10, tzinfo=UTC),
                end=datetime(2026, 6, 10, 23, 59, 59, tzinfo=UTC),
            )
            == 200
        )

    def test_aggregation_over_a_large_dataset_completes(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        from app.analytics import AnalyticsEngine

        generate_dataset(tmp_path / "raw" / "big.log", count=100_000, fmt="json")
        LogPipeline(settings).run(tmp_path / "raw" / "big.log", PipelineOptions(run_id="big"))
        started = time.perf_counter()
        overview = AnalyticsEngine(settings=settings).overview()
        elapsed = time.perf_counter() - started
        assert overview.total_records > 0
        # Columnar aggregation over 100 k rows is a sub-second operation even
        # on modest hardware; anything above this means the scan is not pruned.
        assert elapsed < 10.0


class TestDeduplicationScaling:
    def test_dedup_memory_is_capped(self) -> None:
        from app.core.timeutil import utcnow
        from app.deduplication import ContentHashStrategy, Deduplicator
        from app.models.log_event import LogEvent

        dedup = Deduplicator(ContentHashStrategy(), max_tracked_keys=10_000)
        gc.collect()
        before = memory_usage_mb()
        for index in range(200_000):
            dedup.is_duplicate(
                LogEvent.model_construct(
                    timestamp=utcnow(), raw_message=f"line {index}", message=""
                )
            )
        gc.collect()
        assert len(dedup.seen) == 10_000
        assert memory_usage_mb() - before < 60
