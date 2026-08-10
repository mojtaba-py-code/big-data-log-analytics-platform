"""Kafka source for the stream processor.

Optional: ``pip install 'big-data-log-analytics[kafka]'``.  The processor takes
any iterable, so this module is one possible source rather than a requirement —
which is also why the streaming path is fully testable without a broker.

Offset handling
---------------
Auto-commit is **off**.  Offsets are committed only after
:meth:`~app.streaming.processor.StreamProcessor.process_batch` has flushed the
records to storage, so a crash between the two replays the batch instead of
losing it.  Combined with deterministic ``event_id`` deduplication, that turns
Kafka's at-least-once delivery into effectively-once storage.

Committing before the flush would be the other way round: faster, and silently
lossy on every restart.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from typing import Any

from app.core.config import Settings, get_settings
from app.core.exceptions import ConfigurationError
from app.core.logging import get_logger

log = get_logger(__name__)


class KafkaLogConsumer:
    """Pulls decoded message values from a Kafka topic."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        consumer: Any | None = None,
        encoding: str = "utf-8",
    ) -> None:
        self.settings = settings or get_settings()
        self.config = self.settings.streaming
        self.encoding = encoding
        self._stop = threading.Event()
        self._consumer = consumer or self._build_consumer()

    def _build_consumer(self) -> Any:
        try:
            from confluent_kafka import Consumer
        except ImportError as exc:  # pragma: no cover - optional extra
            raise ConfigurationError(
                "confluent-kafka is not installed; "
                "install with pip install 'big-data-log-analytics[kafka]'"
            ) from exc

        consumer = Consumer(
            {
                "bootstrap.servers": ",".join(self.config.brokers),
                "group.id": self.config.group_id,
                "auto.offset.reset": "latest",
                # Manual commits: see the module docstring.
                "enable.auto.commit": False,
                # One partition's worth of back-pressure, not unbounded buffering.
                "max.partition.fetch.bytes": 1_048_576,
                "session.timeout.ms": 30_000,
            }
        )
        consumer.subscribe([self.config.topic])
        log.info(
            "kafka consumer subscribed",
            extra={"topic": self.config.topic, "group": self.config.group_id},
        )
        return consumer

    def stop(self) -> None:
        self._stop.set()

    def poll_batch(self, limit: int | None = None) -> list[str]:
        """Poll up to ``limit`` messages; an empty list means "nothing yet"."""
        wanted = limit or self.config.max_batch
        messages: list[str] = []
        while len(messages) < wanted and not self._stop.is_set():
            message = self._consumer.poll(self.config.poll_timeout_seconds)
            if message is None:
                break
            if message.error():
                log.warning("kafka message error", extra={"error": str(message.error())})
                continue
            value = message.value()
            if value is None:
                continue
            messages.append(
                value.decode(self.encoding, "replace") if isinstance(value, bytes) else str(value)
            )
        return messages

    def commit(self) -> None:
        """Acknowledge the polled offsets — call only after a successful flush."""
        try:
            self._consumer.commit(asynchronous=False)
        except Exception:  # noqa: BLE001 - a failed commit means a replay, not a loss
            log.warning("kafka offset commit failed; the batch will be replayed")

    def __iter__(self) -> Iterator[str]:
        """Stream messages one at a time (no offset management)."""
        while not self._stop.is_set():
            batch = self.poll_batch()
            if not batch:
                continue
            yield from batch

    def close(self) -> None:
        self.stop()
        try:
            self._consumer.close()
        except Exception:  # noqa: BLE001 - best effort on shutdown
            log.debug("kafka consumer close failed")


def consume(
    settings: Settings | None = None,
    *,
    consumer: Any | None = None,
    parser: str = "json",
    max_batches: int | None = None,
) -> dict[str, Any]:
    """Run the consume → process → flush → commit loop.

    The order is the whole point: records are durable before their offsets are
    acknowledged.
    """
    from app.streaming.processor import StreamProcessor

    config = settings or get_settings()
    if not config.streaming.enabled:
        raise ConfigurationError("streaming is disabled; set streaming.enabled to true")

    source = KafkaLogConsumer(config, consumer=consumer)
    processor = StreamProcessor(config, parser=parser)
    batches = 0
    try:
        while max_batches is None or batches < max_batches:
            messages = source.poll_batch()
            if not messages:
                if source._stop.is_set():
                    break
                continue
            processor.process_batch(messages)
            source.commit()  # only now are the records durable
            batches += 1
    finally:
        processor.flush()
        source.close()
    return processor.snapshot()


__all__ = ["KafkaLogConsumer", "consume"]
