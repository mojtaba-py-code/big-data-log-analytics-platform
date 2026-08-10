"""Descriptive statistics and time-series helpers.

Two consumers:

* The **DuckDB path** computes aggregates in SQL and only uses the helpers here
  to shape results.  This is the default and scales to any dataset size.
* The **streaming path** (real-time consumer, small batches) needs the same
  numbers without a query engine, so exact and approximate implementations
  live here side by side.

Percentiles
-----------
Exact percentiles need the full sorted sample — O(n) memory.  That is fine for
a window of a few thousand points and impossible for a billion, which is why
the SQL path uses DuckDB's ``approx_quantile`` (t-digest) instead.  The two
agree to well within a percent on realistic latency distributions; the exact
version is kept for tests and for small windows where it is free.

Linear interpolation between order statistics is used (the ``numpy``/``pandas``
default), so results match what analysts see elsewhere.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Final

from app.core.timeutil import floor_to_window, iter_windows
from app.models.analytics import CountItem, Stats, TimeSeries, TimeSeriesPoint

#: Percentiles reported by default.
DEFAULT_PERCENTILES: Final[tuple[float, ...]] = (0.5, 0.95, 0.99)


def percentile(values: Sequence[float], q: float) -> float:
    """Exact linear-interpolated percentile of an *unsorted* sample."""
    if not values:
        return 0.0
    if not 0.0 <= q <= 1.0:
        raise ValueError("q must be between 0 and 1")
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = q * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[int(position)])
    weight = position - lower
    return float(ordered[lower] * (1 - weight) + ordered[upper] * weight)


def describe(values: Iterable[float]) -> Stats:
    """Full descriptive statistics in a single pass over a materialised list."""
    data = [float(v) for v in values if v is not None]
    if not data:
        return Stats()
    ordered = sorted(data)
    count = len(ordered)
    total = math.fsum(ordered)  # fsum avoids drift over large samples
    mean = total / count
    variance = (
        math.fsum((value - mean) ** 2 for value in ordered) / (count - 1) if count > 1 else 0.0
    )
    return Stats(
        count=count,
        sum=round(total, 6),
        average=round(mean, 6),
        minimum=ordered[0],
        maximum=ordered[-1],
        median=round(percentile(ordered, 0.5), 6),
        p95=round(percentile(ordered, 0.95), 6),
        p99=round(percentile(ordered, 0.99), 6),
        stddev=round(math.sqrt(variance), 6),
    )


def zscores(values: Sequence[float]) -> list[float]:
    """Standard scores; all zeros when the series has no variance."""
    if len(values) < 2:
        return [0.0] * len(values)
    mean = math.fsum(values) / len(values)
    variance = math.fsum((v - mean) ** 2 for v in values) / (len(values) - 1)
    stddev = math.sqrt(variance)
    if stddev == 0:
        return [0.0] * len(values)
    return [(v - mean) / stddev for v in values]


def moving_average(values: Sequence[float], window: int) -> list[float]:
    """Trailing moving average; the first ``window-1`` points use what exists.

    A trailing (not centred) window is required for anomaly detection: a
    centred window would use future observations, which is fine for a report
    and useless for alerting.
    """
    if window < 1:
        raise ValueError("window must be >= 1")
    out: list[float] = []
    running = 0.0
    for index, value in enumerate(values):
        running += value
        if index >= window:
            running -= values[index - window]
        out.append(running / min(index + 1, window))
    return out


def rolling_std(values: Sequence[float], window: int) -> list[float]:
    """Trailing rolling standard deviation, aligned with :func:`moving_average`."""
    if window < 2:
        raise ValueError("window must be >= 2")
    out: list[float] = []
    for index in range(len(values)):
        chunk = values[max(0, index - window + 1) : index + 1]
        if len(chunk) < 2:
            out.append(0.0)
            continue
        mean = math.fsum(chunk) / len(chunk)
        variance = math.fsum((v - mean) ** 2 for v in chunk) / (len(chunk) - 1)
        out.append(math.sqrt(variance))
    return out


def iqr_bounds(values: Sequence[float], multiplier: float = 1.5) -> tuple[float, float]:
    """Tukey fences.

    IQR is robust: unlike a z-score, a handful of extreme outliers does not
    inflate the threshold that is supposed to catch them.  That makes it the
    better first choice on latency, which is heavily right-skewed.
    """
    if len(values) < 4:
        return (float("-inf"), float("inf"))
    q1 = percentile(values, 0.25)
    q3 = percentile(values, 0.75)
    spread = q3 - q1
    return (q1 - multiplier * spread, q3 + multiplier * spread)


def top_n(counts: dict[str, int], limit: int = 10, *, total: int | None = None) -> list[CountItem]:
    """Rank a count map, attaching each entry's share of the total."""
    denominator = total if total is not None else sum(counts.values())
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    return [
        CountItem(
            key=key,
            count=count,
            percentage=round(count / denominator * 100, 4) if denominator else 0.0,
        )
        for key, count in ranked
    ]


def build_series(
    buckets: dict[datetime, float],
    *,
    metric: str,
    window: str,
    start: datetime | None = None,
    end: datetime | None = None,
    fill_gaps: bool = True,
) -> TimeSeries:
    """Turn a bucket → value map into a gap-filled :class:`TimeSeries`.

    Gap filling matters: an outage produces *no* log records, so the bucket is
    missing rather than zero.  A chart that silently skips it shows a flat line
    through the incident.
    """
    if not buckets:
        return TimeSeries(metric=metric, window=window, points=[])
    first = start or min(buckets)
    last = end or max(buckets)
    if not fill_gaps:
        return TimeSeries(
            metric=metric,
            window=window,
            points=[
                TimeSeriesPoint(bucket=bucket, value=value, count=int(value))
                for bucket, value in sorted(buckets.items())
            ],
        )
    points = [
        TimeSeriesPoint(
            bucket=bucket,
            value=buckets.get(bucket, 0.0),
            count=int(buckets.get(bucket, 0.0)),
        )
        for bucket in iter_windows(first, last, window)
    ]
    return TimeSeries(metric=metric, window=window, points=points)


def bucketize(
    timestamps: Iterable[datetime], window: str, values: Sequence[float] | None = None
) -> dict[datetime, float]:
    """Aggregate timestamps (and optional values) into window buckets."""
    buckets: dict[datetime, float] = {}
    for index, moment in enumerate(timestamps):
        key = floor_to_window(moment, window)
        buckets[key] = buckets.get(key, 0.0) + (values[index] if values else 1.0)
    return buckets


def rate_per_second(count: int, seconds: float) -> float:
    return count / seconds if seconds > 0 else 0.0


def safe_ratio(numerator: float, denominator: float) -> float:
    """Ratio that returns 0.0 rather than raising on an empty denominator."""
    return numerator / denominator if denominator else 0.0


__all__ = [
    "DEFAULT_PERCENTILES",
    "bucketize",
    "build_series",
    "describe",
    "iqr_bounds",
    "moving_average",
    "percentile",
    "rate_per_second",
    "rolling_std",
    "safe_ratio",
    "top_n",
    "zscores",
]
