"""Hive-style partitioning.

Layout
------
``<layer>/year=2026/month=08/day=07/part-<run>-<n>.parquet``

Why partition
-------------
Partitioning turns a full-dataset scan into a directory listing.  A query for
"errors on 2026-08-07" reads one day's directory instead of every file ever
written — the engine *prunes* the rest before opening a single byte.  On a
year of daily logs that is a 365x reduction in I/O, and it is the difference
between a dashboard that answers in 200 ms and one that answers in a minute.

Partitioning also makes retention and re-processing cheap: deleting a day is
``rmtree`` on one directory, and re-running a day overwrites exactly that
directory rather than requiring a delete-by-predicate over a monolith.

Why day granularity by default
------------------------------
Partition granularity is a trade-off against the *small-files problem*: too
many tiny Parquet files and per-file metadata overhead dominates.  Daily
partitions keep files in the 10-500 MB range that Parquet is happiest with for
typical log volumes.  Hourly is available for very high-volume deployments.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Final

from app.core.timeutil import ensure_utc, partition_values

PARTITION_KEYS: Final[tuple[str, ...]] = ("year", "month", "day", "hour")

_PARTITION_SEGMENT: Final[re.Pattern[str]] = re.compile(r"^(year|month|day|hour)=(\d{2,4})$")


def partition_path(
    root: Path, moment: datetime, keys: Sequence[str] = ("year", "month", "day")
) -> Path:
    """Directory for a timestamp, e.g. ``root/year=2026/month=08/day=07``."""
    values = partition_values(ensure_utc(moment))
    path = root
    for key in keys:
        if key not in values:
            raise KeyError(f"unsupported partition key {key!r}; choose from {PARTITION_KEYS}")
        path = path / f"{key}={values[key]}"
    return path


def parse_partition(path: Path) -> dict[str, int]:
    """Extract partition values from a path (inverse of :func:`partition_path`)."""
    found: dict[str, int] = {}
    for part in path.parts:
        match = _PARTITION_SEGMENT.match(part)
        if match:
            found[match.group(1)] = int(match.group(2))
    return found


def partition_datetime(path: Path) -> datetime | None:
    """Reconstruct the partition's start timestamp, if the path has one."""
    values = parse_partition(path)
    if "year" not in values:
        return None
    from datetime import UTC

    return datetime(
        values["year"],
        values.get("month", 1),
        values.get("day", 1),
        values.get("hour", 0),
        tzinfo=UTC,
    )


def iter_partitions(root: Path) -> list[Path]:
    """Every leaf partition directory beneath ``root``, sorted chronologically."""
    if not root.is_dir():
        return []
    leaves: set[Path] = set()
    for candidate in root.rglob("*"):
        if candidate.is_file() and _PARTITION_SEGMENT.match(candidate.parent.name):
            leaves.add(candidate.parent)
    return sorted(leaves, key=_chronological_key)


def _chronological_key(path: Path) -> tuple[int, str]:
    """Sort partitioned directories by time, unpartitioned ones last."""
    moment = partition_datetime(path)
    return (0, moment.isoformat()) if moment else (1, str(path))


def prune_partitions(
    root: Path, start: datetime | None = None, end: datetime | None = None
) -> list[Path]:
    """Partitions overlapping ``[start, end]`` — the core of partition pruning.

    Comparison happens on the *directory names*: no file is opened, which is
    what makes pruning nearly free regardless of dataset size.
    """
    partitions = iter_partitions(root)
    if start is None and end is None:
        return partitions
    start_utc = ensure_utc(start) if start else None
    end_utc = ensure_utc(end) if end else None
    selected: list[Path] = []
    for partition in partitions:
        moment = partition_datetime(partition)
        if moment is None:
            selected.append(partition)  # unpartitioned data is always a candidate
            continue
        values = parse_partition(partition)
        span_end = _partition_end(moment, values)
        if start_utc and span_end <= start_utc:
            continue
        if end_utc and moment > end_utc:
            continue
        selected.append(partition)
    return selected


def _partition_end(start: datetime, values: dict[str, int]) -> datetime:
    from datetime import timedelta

    if "hour" in values:
        return start + timedelta(hours=1)
    if "day" in values:
        return start + timedelta(days=1)
    if "month" in values:
        return (start.replace(day=28) + timedelta(days=4)).replace(day=1)
    return start.replace(year=start.year + 1)


def glob_for_range(
    root: Path,
    start: datetime | None = None,
    end: datetime | None = None,
    *,
    extension: str = "parquet",
) -> list[str]:
    """File globs covering a time range, for DuckDB's ``read_parquet``.

    Returning globs rather than a file list keeps the SQL short (DuckDB expands
    them itself) while still restricting the scan to pruned partitions.
    """
    partitions = prune_partitions(root, start, end)
    if not partitions:
        return []
    return [str(partition / f"*.{extension}") for partition in partitions]


def group_by_partition(
    events: Iterable[object], keys: Sequence[str] = ("year", "month", "day")
) -> dict[tuple[str, ...], list[object]]:
    """Bucket events by their partition key tuple.

    Writers use this to open one file handle per partition instead of
    re-opening a file for every record — the difference between a few hundred
    ``open()`` calls and several million.
    """
    buckets: dict[tuple[str, ...], list[object]] = {}
    for event in events:
        moment = getattr(event, "timestamp", None)
        if not isinstance(moment, datetime):
            continue
        values = partition_values(ensure_utc(moment))
        bucket_key = tuple(values[key] for key in keys)
        buckets.setdefault(bucket_key, []).append(event)
    return buckets


__all__ = [
    "PARTITION_KEYS",
    "glob_for_range",
    "group_by_partition",
    "iter_partitions",
    "parse_partition",
    "partition_datetime",
    "partition_path",
    "prune_partitions",
]
