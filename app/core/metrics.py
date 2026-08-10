"""In-process metrics for pipeline observability.

Responsibility
--------------
Answer, for any run: how many records went in, how many came out, how many were
rejected and why, how long each stage took, and what the peak memory was.

Why not a metrics library?
--------------------------
The platform must run as a CLI on a laptop *and* as a service.  A hard
dependency on a Prometheus client would force a scrape endpoint onto every CLI
invocation.  :class:`MetricsRegistry` is deliberately tiny and exposes
:meth:`MetricsRegistry.to_prometheus`, so wiring it into a real exporter is a
few lines in the API layer.

Thread-safety
-------------
Counters are guarded by a single lock.  Under the platform's parallel model
(processes for CPU-bound parsing, threads for I/O) each worker keeps its own
registry and the parent merges them with :meth:`MetricsRegistry.merge`, so the
lock is never contended on the hot path.
"""

from __future__ import annotations

import threading
import time
from collections import Counter, defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class TimerStats:
    """Aggregated timings for one named stage."""

    count: int = 0
    total_seconds: float = 0.0
    min_seconds: float = float("inf")
    max_seconds: float = 0.0

    def observe(self, seconds: float) -> None:
        self.count += 1
        self.total_seconds += seconds
        self.min_seconds = min(self.min_seconds, seconds)
        self.max_seconds = max(self.max_seconds, seconds)

    @property
    def average_seconds(self) -> float:
        return self.total_seconds / self.count if self.count else 0.0

    def as_dict(self) -> dict[str, float | int]:
        return {
            "count": self.count,
            "total_seconds": round(self.total_seconds, 6),
            "average_seconds": round(self.average_seconds, 6),
            "min_seconds": round(self.min_seconds, 6) if self.count else 0.0,
            "max_seconds": round(self.max_seconds, 6),
        }


@dataclass
class MetricsRegistry:
    """Counters, gauges and timers for a single processing run."""

    counters: Counter[str] = field(default_factory=Counter)
    gauges: dict[str, float] = field(default_factory=dict)
    timers: dict[str, TimerStats] = field(default_factory=lambda: defaultdict(TimerStats))
    labels: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    started_at: float = field(default_factory=time.monotonic)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # -- recording --------------------------------------------------------- #
    def increment(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self.counters[name] += amount

    def increment_label(self, name: str, label: str, amount: int = 1) -> None:
        """Increment a labelled counter, e.g. ``rejections`` by reason."""
        with self._lock:
            self.labels[name][label] += amount
            self.counters[name] += amount

    def set_gauge(self, name: str, value: float) -> None:
        with self._lock:
            self.gauges[name] = value

    def observe(self, name: str, seconds: float) -> None:
        with self._lock:
            self.timers[name].observe(seconds)

    @contextmanager
    def timer(self, name: str) -> Iterator[None]:
        """Time a block, recording it even if the block raises."""
        start = time.perf_counter()
        try:
            yield
        finally:
            self.observe(name, time.perf_counter() - start)

    # -- derived ----------------------------------------------------------- #
    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.started_at

    def rate(self, name: str) -> float:
        """Per-second rate of a counter over the registry's lifetime."""
        elapsed = self.elapsed_seconds
        return self.counters.get(name, 0) / elapsed if elapsed > 0 else 0.0

    def merge(self, other: MetricsRegistry) -> None:
        """Fold a worker's registry into this one."""
        with self._lock:
            self.counters.update(other.counters)
            self.gauges.update(other.gauges)
            for name, stats in other.timers.items():
                target = self.timers[name]
                target.count += stats.count
                target.total_seconds += stats.total_seconds
                target.min_seconds = min(target.min_seconds, stats.min_seconds)
                target.max_seconds = max(target.max_seconds, stats.max_seconds)
            for name, counter in other.labels.items():
                self.labels[name].update(counter)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "elapsed_seconds": round(self.elapsed_seconds, 4),
                "counters": dict(self.counters),
                "gauges": dict(self.gauges),
                "labels": {k: dict(v) for k, v in self.labels.items()},
                "timers": {k: v.as_dict() for k, v in self.timers.items()},
            }

    def to_prometheus(self, prefix: str = "loga") -> str:
        """Render the registry in Prometheus text exposition format."""
        lines: list[str] = []
        snap = self.snapshot()
        for name, value in sorted(snap["counters"].items()):
            lines.append(f"{prefix}_{_safe(name)}_total {value}")
        for name, value in sorted(snap["gauges"].items()):
            lines.append(f"{prefix}_{_safe(name)} {value}")
        for name, buckets in sorted(snap["labels"].items()):
            for label, value in sorted(buckets.items()):
                lines.append(f'{prefix}_{_safe(name)}{{reason="{_safe(label)}"}} {value}')
        for name, stats in sorted(snap["timers"].items()):
            lines.append(f"{prefix}_{_safe(name)}_seconds_sum {stats['total_seconds']}")
            lines.append(f"{prefix}_{_safe(name)}_seconds_count {stats['count']}")
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        with self._lock:
            self.counters.clear()
            self.gauges.clear()
            self.timers.clear()
            self.labels.clear()
            self.started_at = time.monotonic()


def _safe(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in name)


def memory_usage_mb() -> float:
    """Resident set size of the current process in MiB (0.0 if unavailable)."""
    try:
        import psutil

        rss: int = psutil.Process().memory_info().rss
        return rss / 1024**2
    except Exception:  # noqa: BLE001 - psutil is optional at runtime
        return 0.0


#: Registry used by long-lived services (API, workers).  Batch runs create
#: their own so their numbers describe exactly one job.
global_metrics = MetricsRegistry()


__all__ = ["MetricsRegistry", "TimerStats", "global_metrics", "memory_usage_mb"]
