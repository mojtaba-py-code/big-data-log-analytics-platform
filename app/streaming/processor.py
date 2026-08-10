"""Near-real-time stream processing.

    producer → broker → consumer → parse → validate → dedup → ┬─→ live window
                                                              └─→ storage

Why this is separate from the batch pipeline
--------------------------------------------
They optimise for opposite things.  Batch maximises **throughput**: buffer tens
of thousands of records, write large Parquet row-groups, never flush early.
Streaming minimises **latency**: a record must become queryable within seconds,
so the writer flushes on a timer as well as on a size threshold, producing more
and smaller files.  Forcing one component to do both means it does neither well
— so the stages are reused and the *scheduling* differs.

Delivery semantics
------------------
The processor is designed for an at-least-once broker.  It flushes storage
**before** acknowledging, so a crash between the two replays records rather
than losing them, and deduplication (deterministic ``event_id``) collapses the
replay.  That is the pairing that turns at-least-once transport into
effectively-once storage.

Back-pressure
-------------
The processor pulls.  It never buffers more than ``max_batch`` records, so a
producer that outruns it is slowed by the consumer not polling, rather than by
this process growing until it is killed.

Testability
-----------
:class:`StreamProcessor` consumes any iterable of messages.  Kafka is one
possible source (:mod:`app.streaming.kafka_consumer`); a list is another, which
is why the whole path is testable without a broker.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from app.core.config import Settings, get_settings
from app.core.logging import get_logger, set_request_id
from app.core.masking import Masker
from app.core.metrics import MetricsRegistry
from app.core.timeutil import utcnow
from app.deduplication import Deduplicator
from app.models.enums import RejectReason, SourceType
from app.models.log_event import LogEvent
from app.parsers import ParseContext, get_parser
from app.parsers.structured import StructuredParser
from app.storage import StorageBackend, build_store
from app.transformation import TransformationChain
from app.validation import DeadLetterQueue, NullDeadLetterQueue, RecordValidator

log = get_logger(__name__)


@dataclass(slots=True)
class StreamStats:
    """Counters for a running stream."""

    messages: int = 0
    parsed: int = 0
    valid: int = 0
    rejected: int = 0
    duplicates: int = 0
    written: int = 0
    flushes: int = 0
    started_at: float = field(default_factory=time.monotonic)
    last_flush_at: float = field(default_factory=time.monotonic)

    @property
    def uptime_seconds(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def messages_per_second(self) -> float:
        return self.messages / self.uptime_seconds if self.uptime_seconds > 0 else 0.0

    def as_dict(self) -> dict[str, float | int]:
        return {
            "messages": self.messages,
            "parsed": self.parsed,
            "valid": self.valid,
            "rejected": self.rejected,
            "duplicates": self.duplicates,
            "written": self.written,
            "flushes": self.flushes,
            "uptime_seconds": round(self.uptime_seconds, 2),
            "messages_per_second": round(self.messages_per_second, 2),
        }


class LiveWindow:
    """A bounded, rolling view of the most recent events.

    Exists so a dashboard can show "the last five minutes" without querying
    storage — the newest records may not have been flushed yet, and a scan is
    far too expensive to run per second.

    Bounded twice over: by age *and* by count.  Age alone is not enough — a
    traffic burst inside the window would still grow without limit.
    """

    __slots__ = ("_events", "_lock", "max_age", "max_events")

    def __init__(self, max_age: timedelta = timedelta(minutes=5), max_events: int = 10_000):
        self.max_age = max_age
        self.max_events = max_events
        self._events: deque[LogEvent] = deque(maxlen=max_events)
        self._lock = threading.Lock()

    def add(self, event: LogEvent) -> None:
        with self._lock:
            self._events.append(event)

    def _prune(self, now: datetime) -> None:
        cutoff = now - self.max_age
        while self._events and self._events[0].timestamp < cutoff:
            self._events.popleft()

    def snapshot(self) -> dict[str, Any]:
        """Current metrics over the window."""
        now = utcnow()
        with self._lock:
            self._prune(now)
            events = list(self._events)

        if not events:
            return {"window_seconds": self.max_age.total_seconds(), "events": 0}

        errors = sum(1 for event in events if event.is_error)
        latencies = sorted(
            event.response_time_ms for event in events if event.response_time_ms is not None
        )
        services: dict[str, int] = {}
        for event in events:
            if event.service:
                services[event.service] = services.get(event.service, 0) + 1

        return {
            "window_seconds": self.max_age.total_seconds(),
            "events": len(events),
            "errors": errors,
            "error_rate": round(errors / len(events), 6),
            "events_per_second": round(len(events) / self.max_age.total_seconds(), 3),
            "p95_latency_ms": round(latencies[int(len(latencies) * 0.95)], 3) if latencies else 0.0,
            "services": dict(sorted(services.items(), key=lambda kv: -kv[1])[:10]),
            "oldest": events[0].timestamp,
            "newest": events[-1].timestamp,
        }

    def __len__(self) -> int:
        return len(self._events)


class StreamProcessor:
    """Runs the pipeline stages over a live message stream."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        parser: str = "json",
        store: StorageBackend | None = None,
        dlq: DeadLetterQueue | None = None,
        window: LiveWindow | None = None,
        metrics: MetricsRegistry | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        stream = self.settings.streaming
        self.max_batch = stream.max_batch
        self.flush_interval = stream.flush_interval_seconds

        self.parser = get_parser(parser)
        self.context = ParseContext(source=f"stream:{stream.topic}", source_type=SourceType.STREAM)
        self.transformer = TransformationChain.from_settings(self.settings)
        self.validator = RecordValidator(self.settings.validation)
        self.deduplicator = Deduplicator.from_settings(self.settings.deduplication)

        self.store = store or build_store(self.settings.processed_path, self.settings)
        self.dlq = dlq or NullDeadLetterQueue()
        self.window = window or LiveWindow()
        self.metrics = metrics or MetricsRegistry()
        self.stats = StreamStats()

        self._buffer: list[LogEvent] = []
        self._flush_sequence = 0
        self._stop = threading.Event()
        self._masker = Masker(
            rules=self.settings.masking.rules, enabled=self.settings.masking.enabled
        )

    # -- lifecycle ----------------------------------------------------------- #
    def stop(self) -> None:
        """Ask the loop to finish after the current batch."""
        self._stop.set()

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    # -- processing ---------------------------------------------------------- #
    def handle(self, message: str | Mapping[str, Any]) -> LogEvent | None:
        """Process one message; return the event when it was accepted.

        Never raises for a bad message — a stream must not die because one
        producer emitted nonsense.
        """
        self.stats.messages += 1
        try:
            if isinstance(message, str):
                event = self.parser.parse(message, self.context)
            elif isinstance(self.parser, StructuredParser):
                event = self.parser.parse_record(message, self.context)
            else:
                from app.parsers.structured import JsonLineParser

                event = JsonLineParser().parse_record(message, self.context)
        except Exception as exc:  # noqa: BLE001 - a bad message is data, not a fault
            self._reject(message, RejectReason.UNPARSEABLE, "parse", str(exc))
            return None

        self.stats.parsed += 1

        try:
            event = self.transformer.apply(event)
        except Exception as exc:  # noqa: BLE001
            self._reject(message, RejectReason.TRANSFORM_ERROR, "transform", str(exc))
            return None

        outcome = self.validator.validate(event)
        if not outcome.valid:
            issue = outcome.fatal_issue
            self._reject(
                message,
                issue.reason if issue else RejectReason.SCHEMA_VIOLATION,
                "validate",
                issue.detail if issue else "",
            )
            return None
        self.stats.valid += 1

        if self.deduplicator.is_duplicate(event):
            self.stats.duplicates += 1
            return None

        self._buffer.append(event)
        self.window.add(event)
        return event

    def _reject(
        self, message: str | Mapping[str, Any], reason: RejectReason, stage: str, detail: str
    ) -> None:
        self.stats.rejected += 1
        self.metrics.increment_label("stream_rejections", str(reason))
        raw = message if isinstance(message, str) else str(message)
        self.dlq.record(
            self._masker.mask_text(raw)[:8_192],
            reason,
            stage=stage,
            detail=detail,
            source=self.context.source,
        )

    # -- flushing ------------------------------------------------------------ #
    def should_flush(self) -> bool:
        """Flush on size *or* age — whichever comes first.

        Size alone starves a quiet topic (records could sit unqueryable for
        hours); age alone produces a file per tick under load.
        """
        if not self._buffer:
            return False
        if len(self._buffer) >= self.max_batch:
            return True
        return time.monotonic() - self.stats.last_flush_at >= self.flush_interval

    def flush(self) -> int:
        """Write the buffer and return how many records were persisted."""
        if not self._buffer:
            self.stats.last_flush_at = time.monotonic()
            return 0
        batch, self._buffer = self._buffer, []
        # The run id becomes the output filename, and the writer replaces a file
        # of the same name rather than appending.  A wall-clock second is not
        # unique enough — two flushes inside one second would silently destroy
        # the first batch — so the id carries the pid and a monotonic counter.
        self._flush_sequence += 1
        run_id = f"stream-{os.getpid()}-{int(time.time())}-{self._flush_sequence:06d}"
        try:
            self.store.write(batch, run_id=run_id)
            self.store.flush()
        except Exception:
            # Put the batch back: the caller has not acknowledged the offsets
            # yet, so a retry (or a restart) will replay it rather than lose it.
            self._buffer = batch + self._buffer
            log.exception("stream flush failed; records retained for retry")
            raise
        self.stats.written += len(batch)
        self.stats.flushes += 1
        self.stats.last_flush_at = time.monotonic()
        self.metrics.increment("stream_records_written", len(batch))
        log.info(
            "stream batch flushed",
            extra={"records": len(batch), "run_id": run_id, "buffered": len(self._buffer)},
        )
        return len(batch)

    # -- the loop ------------------------------------------------------------ #
    def run(self, messages: Iterable[str | Mapping[str, Any]]) -> StreamStats:
        """Consume until the source is exhausted or :meth:`stop` is called."""
        set_request_id()
        log.info(
            "stream processor started",
            extra={
                "parser": self.parser.name,
                "max_batch": self.max_batch,
                "flush_interval": self.flush_interval,
            },
        )
        try:
            for message in messages:
                if self.stopping:
                    break
                self.handle(message)
                if self.should_flush():
                    self.flush()
        finally:
            # Always drain: a stopped stream must not strand buffered records.
            self.flush()
            self.dlq.close()
            log.info("stream processor stopped", extra=self.stats.as_dict())
        return self.stats

    def process_batch(self, messages: Iterable[str | Mapping[str, Any]]) -> int:
        """Handle a batch and flush it — the unit a consumer loop acknowledges."""
        for message in messages:
            self.handle(message)
        return self.flush()

    def snapshot(self) -> dict[str, Any]:
        return {
            "stats": self.stats.as_dict(),
            "buffered": len(self._buffer),
            "live_window": self.window.snapshot(),
            "deduplication": self.deduplicator.snapshot(),
        }


def iter_with_timeout(
    source: Iterable[Any], stop: threading.Event, poll_seconds: float = 1.0
) -> Iterator[Any]:
    """Yield from ``source`` until ``stop`` is set.

    A thin adapter so a blocking consumer can still honour a shutdown signal.
    """
    for item in source:
        if stop.is_set():
            return
        if item is None:
            time.sleep(poll_seconds)
            continue
        yield item


__all__ = ["LiveWindow", "StreamProcessor", "StreamStats", "iter_with_timeout"]
