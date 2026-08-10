"""Near-real-time streaming layer.

Deliberately separate from :mod:`app.pipeline`: the two reuse the same stages
but schedule them for opposite goals — batch for throughput, streaming for
latency.  See :mod:`app.streaming.processor`.

The Kafka consumer is an optional extra; the processor itself takes any
iterable, so the whole path is testable without a broker.
"""

from __future__ import annotations

from app.streaming.processor import LiveWindow, StreamProcessor, StreamStats

__all__ = ["LiveWindow", "StreamProcessor", "StreamStats"]
