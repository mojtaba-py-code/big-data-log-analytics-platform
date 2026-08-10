"""Streaming path tests.

No broker is involved: the processor consumes any iterable, which is exactly
why the design is testable.  A fake Kafka consumer covers the offset-ordering
contract that matters for delivery semantics.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.core.config import Settings
from app.storage import DuckDBEngine
from app.streaming import LiveWindow, StreamProcessor
from app.validation import DeadLetterQueue

pytestmark = pytest.mark.integration


def message(index: int, moment: datetime, *, level: str = "INFO", status: int = 200) -> str:
    return json.dumps(
        {
            "timestamp": moment.isoformat(),
            "level": level,
            "service": "api",
            "message": f"event {index}",
            "status": status,
            "duration_ms": float(10 + index % 50),
            "client_ip": f"192.0.2.{index % 200 + 1}",
        }
    )


@pytest.fixture
def stream_settings(settings: Settings) -> Settings:
    """Small batches and a short flush interval, so tests exercise both paths."""
    return settings.model_copy(
        update={
            "streaming": settings.streaming.model_copy(
                update={"enabled": True, "max_batch": 10, "flush_interval_seconds": 0.05}
            )
        }
    )


class TestStreamProcessor:
    def test_messages_become_queryable_records(
        self, stream_settings: Settings, base_time: datetime
    ) -> None:
        processor = StreamProcessor(stream_settings)
        messages = [message(i, base_time + timedelta(seconds=i)) for i in range(25)]
        stats = processor.run(messages)

        assert stats.messages == 25
        assert stats.written == 25
        assert stats.rejected == 0

        engine = DuckDBEngine(stream_settings.processed_path)
        assert engine.dataset_summary()["records"] == 25

    def test_flushes_on_batch_size(self, stream_settings: Settings, base_time: datetime) -> None:
        processor = StreamProcessor(stream_settings)
        for index in range(10):
            processor.handle(message(index, base_time + timedelta(seconds=index)))
        assert processor.should_flush()  # max_batch reached
        assert processor.flush() == 10

    def test_flushes_on_age_for_a_quiet_topic(
        self, stream_settings: Settings, base_time: datetime
    ) -> None:
        """A trickle of traffic must not sit unqueryable until a batch fills."""
        processor = StreamProcessor(stream_settings)
        processor.handle(message(0, base_time))
        assert not processor.should_flush()  # one record, batch not full
        time.sleep(0.06)  # past flush_interval_seconds
        assert processor.should_flush()
        assert processor.flush() == 1

    def test_empty_buffer_flush_is_a_no_op(self, stream_settings: Settings) -> None:
        processor = StreamProcessor(stream_settings)
        assert processor.flush() == 0
        assert not processor.should_flush()

    def test_bad_messages_are_dead_lettered_not_fatal(
        self, stream_settings: Settings, base_time: datetime, tmp_path: Path
    ) -> None:
        dlq = DeadLetterQueue(tmp_path / "rejected", run_id="stream")
        processor = StreamProcessor(stream_settings, dlq=dlq)
        stats = processor.run(
            [
                message(0, base_time),
                "this is not json",
                "{broken",
                message(1, base_time + timedelta(seconds=1)),
            ]
        )
        assert stats.messages == 4
        assert stats.written == 2
        assert stats.rejected == 2
        assert dlq.counts()["unparseable"] == 2

    def test_duplicates_are_collapsed(self, stream_settings: Settings, base_time: datetime) -> None:
        """At-least-once delivery replays messages; dedup makes that harmless."""
        processor = StreamProcessor(stream_settings)
        duplicated = [message(0, base_time)] * 8
        stats = processor.run(duplicated)
        assert stats.messages == 8
        assert stats.written == 1
        assert stats.duplicates == 7

    def test_secrets_are_masked_on_the_stream_path_too(
        self, stream_settings: Settings, base_time: datetime
    ) -> None:
        payload = json.dumps(
            {
                "timestamp": base_time.isoformat(),
                "message": "login password=StreamSecret1 for a@b.test",
            }
        )
        StreamProcessor(stream_settings).run([payload])
        stored = b"".join(f.read_bytes() for f in stream_settings.processed_path.rglob("*.parquet"))
        assert b"StreamSecret1" not in stored
        assert b"a@b.test" not in stored

    def test_stop_drains_the_buffer(self, stream_settings: Settings, base_time: datetime) -> None:
        """A stopped stream must not strand records it already accepted."""
        processor = StreamProcessor(stream_settings)

        def messages() -> Any:
            for index in range(100):
                if index == 5:
                    processor.stop()
                yield message(index, base_time + timedelta(seconds=index))

        stats = processor.run(messages())
        assert stats.messages <= 6
        assert stats.written == stats.messages - stats.rejected - stats.duplicates

    def test_failed_flush_retains_the_batch(
        self, stream_settings: Settings, base_time: datetime
    ) -> None:
        """Records stay buffered so the caller can retry instead of losing them."""

        class BrokenStore:
            records_written = 0
            files_written: list[Path] = []

            def write(self, *_: object, **__: object) -> None:
                raise OSError("disk full")

            def flush(self) -> None: ...

        processor = StreamProcessor(stream_settings, store=BrokenStore())  # type: ignore[arg-type]
        processor.handle(message(0, base_time))
        with pytest.raises(OSError):
            processor.flush()
        assert len(processor._buffer) == 1

    def test_snapshot_reports_live_state(
        self, stream_settings: Settings, base_time: datetime
    ) -> None:
        processor = StreamProcessor(stream_settings)
        processor.run([message(i, base_time + timedelta(seconds=i)) for i in range(12)])
        snapshot = processor.snapshot()
        assert snapshot["stats"]["written"] == 12
        assert snapshot["live_window"]["events"] >= 0
        assert snapshot["deduplication"]["unique"] == 12


class TestLiveWindow:
    def test_reports_metrics_without_touching_storage(self, base_time: datetime) -> None:
        from app.models.log_event import LogEvent

        window = LiveWindow(max_age=timedelta(hours=12))
        for index in range(20):
            window.add(
                LogEvent.build(
                    timestamp=base_time + timedelta(seconds=index),
                    level="ERROR" if index % 4 == 0 else "INFO",
                    service="api",
                    message="x",
                    response_time_ms=float(index),
                )
            )
        snapshot = window.snapshot()
        assert snapshot["events"] == 20
        assert snapshot["errors"] == 5
        assert snapshot["error_rate"] == pytest.approx(0.25)
        assert snapshot["services"] == {"api": 20}

    def test_is_bounded_by_count(self, base_time: datetime) -> None:
        from app.models.log_event import LogEvent

        window = LiveWindow(max_age=timedelta(hours=1), max_events=50)
        for index in range(500):
            window.add(LogEvent.build(timestamp=base_time + timedelta(seconds=index), message="x"))
        assert len(window) == 50

    def test_is_bounded_by_age(self) -> None:
        from app.core.timeutil import utcnow
        from app.models.log_event import LogEvent

        window = LiveWindow(max_age=timedelta(seconds=1))
        now = utcnow()
        window.add(LogEvent.build(timestamp=now - timedelta(hours=1), message="old"))
        window.add(LogEvent.build(timestamp=now, message="fresh"))
        assert window.snapshot()["events"] == 1

    def test_empty_window(self) -> None:
        assert LiveWindow().snapshot()["events"] == 0


class TestKafkaConsumer:
    """The offset contract, without a broker."""

    class FakeKafkaMessage:
        def __init__(self, value: bytes) -> None:
            self._value = value

        def error(self) -> None:
            return None

        def value(self) -> bytes:
            return self._value

    class FakeConsumer:
        def __init__(self, payloads: list[bytes]) -> None:
            self._payloads = list(payloads)
            self.commits = 0
            self.closed = False

        def poll(self, _timeout: float) -> Any:
            if not self._payloads:
                return None
            return TestKafkaConsumer.FakeKafkaMessage(self._payloads.pop(0))

        def commit(self, asynchronous: bool = False) -> None:  # noqa: ARG002
            self.commits += 1

        def close(self) -> None:
            self.closed = True

    def test_polls_and_decodes(self, stream_settings: Settings, base_time: datetime) -> None:
        from app.streaming.kafka_consumer import KafkaLogConsumer

        payloads = [message(i, base_time + timedelta(seconds=i)).encode() for i in range(5)]
        source = KafkaLogConsumer(stream_settings, consumer=self.FakeConsumer(payloads))
        batch = source.poll_batch()
        assert len(batch) == 5
        assert json.loads(batch[0])["service"] == "api"

    def test_offsets_are_committed_only_after_a_successful_flush(
        self, stream_settings: Settings, base_time: datetime
    ) -> None:
        from app.streaming.kafka_consumer import consume

        payloads = [message(i, base_time + timedelta(seconds=i)).encode() for i in range(6)]
        fake = self.FakeConsumer(payloads)
        snapshot = consume(stream_settings, consumer=fake, max_batches=1)

        assert snapshot["stats"]["written"] == 6
        assert fake.commits == 1  # exactly one commit, after the flush
        assert fake.closed

    def test_streaming_must_be_enabled(self, settings: Settings) -> None:
        from app.core.exceptions import ConfigurationError
        from app.streaming.kafka_consumer import consume

        with pytest.raises(ConfigurationError, match="disabled"):
            consume(settings, consumer=self.FakeConsumer([]))
