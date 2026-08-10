"""End-to-end pipeline and storage integration tests."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from app.core.config import Settings
from app.models.enums import RejectReason
from app.models.log_event import LogEvent
from app.pipeline import LogPipeline, PipelineOptions, process_parallel
from app.storage import CsvStore, DuckDBEngine, JsonlStore, MetadataStore, ParquetStore
from app.storage.partitioning import (
    iter_partitions,
    parse_partition,
    partition_path,
    prune_partitions,
)
from app.validation.dlq import DeadLetterQueue, iter_rejected, rejection_stats

pytestmark = pytest.mark.integration


class TestPipeline:
    def test_ingests_a_json_log_file(self, settings: Settings, log_file: Path) -> None:
        result = LogPipeline(settings).run(log_file, PipelineOptions(run_id="run1"))
        assert result.succeeded
        assert result.records_written == 4  # 5 lines, 1 malformed
        assert result.records_rejected == 1
        assert result.rejection_reasons[str(RejectReason.UNPARSEABLE)] == 1
        assert result.outputs

    def test_malformed_records_reach_the_dead_letter_queue(
        self, settings: Settings, log_file: Path
    ) -> None:
        LogPipeline(settings).run(log_file, PipelineOptions(run_id="run2"))
        rejected = list(iter_rejected(settings.rejected_path))
        assert len(rejected) == 1
        assert rejected[0]["reason"] == str(RejectReason.UNPARSEABLE)
        assert "not valid json" in rejected[0]["raw"]

    def test_rejection_stats_aggregate(self, settings: Settings, log_file: Path) -> None:
        LogPipeline(settings).run(log_file, PipelineOptions(run_id="run3"))
        assert rejection_stats(settings.rejected_path)["unparseable"] == 1

    def test_access_log_ingestion(self, settings: Settings, access_log_file: Path) -> None:
        result = LogPipeline(settings).run(access_log_file, PipelineOptions(run_id="acc"))
        assert result.records_written == 4
        engine = DuckDBEngine(settings.processed_path)
        rows = engine.query_logs(limit=10)
        assert {row["status_code"] for row in rows} == {200, 201, 404, 500}

    def test_dry_run_writes_nothing(self, settings: Settings, log_file: Path) -> None:
        result = LogPipeline(settings).run(log_file, PipelineOptions(run_id="dry", dry_run=True))
        assert result.records_written == 0
        assert not list(settings.processed_path.rglob("*.parquet"))

    def test_reingestion_is_idempotent(self, settings: Settings, log_file: Path) -> None:
        """Same input, same run id => same ids and the same output file."""
        first = LogPipeline(settings).run(log_file, PipelineOptions(run_id="same"))
        second = LogPipeline(settings).run(log_file, PipelineOptions(run_id="same"))
        assert first.outputs == second.outputs
        engine = DuckDBEngine(settings.processed_path)
        rows = engine.query_logs(limit=100)
        assert len({row["event_id"] for row in rows}) == len(rows)

    def test_limit_stops_early(self, settings: Settings, log_file: Path) -> None:
        result = LogPipeline(settings).run(log_file, PipelineOptions(run_id="lim", limit=2))
        assert result.records_written <= 2

    def test_gzipped_input(self, settings: Settings, tmp_path: Path) -> None:
        path = tmp_path / "raw" / "app.log.gz"
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = "\n".join(
            json.dumps({"timestamp": "2026-08-07T12:00:00Z", "message": f"m{i}"}) for i in range(50)
        )
        with gzip.open(path, "wt", encoding="utf-8") as stream:
            stream.write(payload)
        result = LogPipeline(settings).run(path, PipelineOptions(run_id="gz"))
        assert result.records_written == 50

    def test_csv_input(self, settings: Settings, tmp_path: Path) -> None:
        path = tmp_path / "raw" / "logs.csv"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "timestamp,level,service,message,status\n"
            "2026-08-07T12:00:00Z,INFO,api,started,200\n"
            "2026-08-07T12:00:01Z,ERROR,api,failed,500\n",
            encoding="utf-8",
        )
        result = LogPipeline(settings).run(path, PipelineOptions(run_id="csv"))
        assert result.records_written == 2

    def test_duplicates_are_removed(self, settings: Settings, tmp_path: Path) -> None:
        path = tmp_path / "raw" / "dupes.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"timestamp": "2026-08-07T12:00:00Z", "message": "same"})
        path.write_text("\n".join([line] * 10), encoding="utf-8")
        result = LogPipeline(settings).run(path, PipelineOptions(run_id="dup"))
        assert result.records_written == 1
        assert result.records_duplicate == 9

    def test_directory_ingestion(self, settings: Settings, tmp_path: Path) -> None:
        directory = tmp_path / "raw" / "many"
        directory.mkdir(parents=True)
        for index in range(3):
            (directory / f"file{index}.log").write_text(
                json.dumps({"timestamp": "2026-08-07T12:00:00Z", "message": f"m{index}"}),
                encoding="utf-8",
            )
        result = LogPipeline(settings).run(directory, PipelineOptions(run_id="dir"))
        assert result.records_written == 3

    def test_parallel_processing_matches_sequential(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        files = []
        for index in range(3):
            path = tmp_path / "raw" / f"p{index}.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "\n".join(
                    json.dumps({"timestamp": "2026-08-07T12:00:00Z", "message": f"f{index}-{n}"})
                    for n in range(20)
                ),
                encoding="utf-8",
            )
            files.append(path)
        result = process_parallel(files, settings, PipelineOptions(run_id="par"), workers=1)
        assert result.records_written == 60

    def test_secrets_never_reach_storage(self, settings: Settings, tmp_path: Path) -> None:
        path = tmp_path / "raw" / "leaky.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "timestamp": "2026-08-07T12:00:00Z",
                    "message": "auth ok password=SuperSecret123 for user@example.com",
                }
            ),
            encoding="utf-8",
        )
        LogPipeline(settings).run(path, PipelineOptions(run_id="leak"))
        stored = b"".join(file.read_bytes() for file in settings.processed_path.rglob("*.parquet"))
        assert b"SuperSecret123" not in stored
        assert b"user@example.com" not in stored

    def test_run_aborts_when_rejection_rate_is_hopeless(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        path = tmp_path / "raw" / "garbage.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        # JSON is detected from the head, then everything after it is garbage.
        good = json.dumps({"timestamp": "2026-08-07T12:00:00Z", "message": "ok"})
        path.write_text("\n".join([good] * 30 + ["{{{ broken"] * 12_000), encoding="utf-8")
        result = LogPipeline(settings).run(path, PipelineOptions(run_id="abort"))
        assert not result.succeeded
        assert any("rejection rate" in error for error in result.errors)


class TestStorage:
    def test_parquet_round_trip(self, settings: Settings, sample_events: list[LogEvent]) -> None:
        store = ParquetStore(settings.processed_path, batch_size=1_000)
        store.write(sample_events, run_id="t")
        store.flush()
        rows = list(store.read())
        assert len(rows) == len(sample_events)
        assert store.row_count() == len(sample_events)

    def test_partitioning_by_date(
        self, settings: Settings, sample_events: list[LogEvent], base_time
    ) -> None:
        store = ParquetStore(settings.processed_path)
        store.write(sample_events, run_id="t")
        store.flush()
        partitions = iter_partitions(settings.processed_path)
        assert partitions
        assert parse_partition(partitions[0])["year"] == base_time.year

    def test_partition_pruning_narrows_the_scan(
        self, settings: Settings, sample_events: list[LogEvent], base_time
    ) -> None:
        from datetime import timedelta

        store = ParquetStore(settings.processed_path)
        store.write(sample_events, run_id="t")
        store.flush()
        selected = prune_partitions(
            settings.processed_path, base_time - timedelta(days=30), base_time - timedelta(days=20)
        )
        assert selected == []

    def test_temp_files_are_not_visible_to_readers(
        self, settings: Settings, sample_events: list[LogEvent]
    ) -> None:
        store = ParquetStore(settings.processed_path)
        store.write(sample_events[:10], run_id="t")
        # Before flush() the data lives in a hidden .tmp file.
        assert not list(settings.processed_path.rglob("*.parquet"))
        store.flush()
        assert list(settings.processed_path.rglob("*.parquet"))

    def test_jsonl_store(self, settings: Settings, sample_events: list[LogEvent]) -> None:
        store = JsonlStore(settings.processed_path / "jsonl")
        store.write(sample_events[:20], run_id="t")
        store.flush()
        assert len(list(store.read())) == 20

    def test_csv_store_quotes_embedded_separators(self, settings: Settings) -> None:
        from app.core.timeutil import utcnow

        store = CsvStore(settings.processed_path / "csv")
        store.write(
            [LogEvent.build(timestamp=utcnow(), message='a,b "quoted" and\nnewline')],
            run_id="t",
        )
        store.flush()
        rows = list(store.read())
        assert len(rows) == 1

    def test_partition_path_layout(self, base_time, tmp_path: Path) -> None:
        path = partition_path(tmp_path, base_time)
        assert path.parts[-3:] == (
            f"year={base_time.year:04d}",
            f"month={base_time.month:02d}",
            f"day={base_time.day:02d}",
        )


class TestDuckDBEngine:
    def test_summary_and_counts(self, settings: Settings, populated_store: Path) -> None:
        engine = DuckDBEngine(populated_store)
        summary = engine.dataset_summary()
        assert summary["records"] == 200
        assert engine.count_logs("level = ?", ["ERROR"]) == 50

    def test_query_returns_utc_timestamps(self, populated_store: Path) -> None:
        engine = DuckDBEngine(populated_store)
        row = engine.query_logs(limit=1)[0]
        assert row["timestamp"].utcoffset().total_seconds() == 0

    def test_unknown_column_is_rejected(self, populated_store: Path) -> None:
        from app.core.exceptions import QueryError

        engine = DuckDBEngine(populated_store)
        with pytest.raises(QueryError):
            engine.query_logs(columns=["secret_column"])

    def test_empty_dataset_yields_no_source(self, tmp_path: Path) -> None:
        engine = DuckDBEngine(tmp_path / "nothing")
        assert engine.source_expression() is None
        assert engine.count_logs() == 0


class TestMetadataStore:
    def test_run_lifecycle(self, settings: Settings) -> None:
        from app.models.results import PipelineResult

        store = MetadataStore.from_settings(settings)
        store.create_schema()
        store.start_run("r1", sources=["a.log"])
        result = PipelineResult(run_id="r1", records_written=10, lines_read=12)
        store.finish_run(result)
        runs = store.recent_runs()
        assert runs[0]["run_id"] == "r1"
        assert runs[0]["status"] == "succeeded"
        assert store.run_stats()["records_written"] == 10
        store.close()

    def test_checkpoints(self, settings: Settings) -> None:
        store = MetadataStore.from_settings(settings)
        store.create_schema()
        store.save_checkpoint("a.log", last_offset=500)
        assert store.get_checkpoint("a.log").last_offset == 500
        store.save_checkpoint("a.log", last_offset=900)
        assert store.get_checkpoint("a.log").last_offset == 900
        store.close()

    def test_api_key_lifecycle(self, settings: Settings) -> None:
        store = MetadataStore.from_settings(settings)
        store.create_schema()
        secret = store.create_api_key("ci", ["read", "write"])
        record = store.verify_api_key(secret)
        assert record is not None
        assert record.scope_set() == {"read", "write"}
        assert store.revoke_api_key("ci")
        assert store.verify_api_key(secret) is None
        store.close()

    def test_keys_are_not_stored_in_plaintext(self, settings: Settings) -> None:
        store = MetadataStore.from_settings(settings)
        store.create_schema()
        secret = store.create_api_key("ci")
        store.close()
        assert secret.encode() not in settings.database.sqlite_path.read_bytes()


class TestDeadLetterQueue:
    def test_records_are_written_and_counted(self, tmp_path: Path) -> None:
        with DeadLetterQueue(tmp_path / "rejected", run_id="r") as dlq:
            dlq.record("bad line", RejectReason.UNPARSEABLE, stage="parse")
            dlq.record("worse", RejectReason.INVALID_IP, stage="validate")
        assert dlq.counts() == {"unparseable": 1, "invalid_ip": 1}
        assert len(list(iter_rejected(tmp_path / "rejected"))) == 2

    def test_payloads_are_masked(self, tmp_path: Path) -> None:
        with DeadLetterQueue(tmp_path / "rejected", run_id="r") as dlq:
            dlq.record("password=hunter2 broke", RejectReason.UNPARSEABLE, stage="parse")
        stored = next(iter_rejected(tmp_path / "rejected"))
        assert "hunter2" not in stored["raw"]

    def test_cap_bounds_writes_but_not_counts(self, tmp_path: Path) -> None:
        with DeadLetterQueue(tmp_path / "rejected", run_id="r", max_records=5) as dlq:
            for index in range(50):
                dlq.record(f"line {index}", RejectReason.UNPARSEABLE, stage="parse")
        assert dlq.total == 50
        assert dlq.written == 5
