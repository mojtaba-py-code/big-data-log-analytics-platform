"""Timestamp parsing, normalisation and time-window bucketing.

Every timestamp in the platform is **timezone-aware UTC**.  Naive datetimes are
the single largest source of silent corruption in log analytics: a naive value
compared against an aware one raises, and a naive value *assumed* to be local
shifts entire dashboards by hours.  Normalisation happens once, here.

Performance
-----------
``parse_timestamp`` is called once per record, so it is ordered cheapest-first:
epoch detection → ``datetime.fromisoformat`` (C-implemented) → a small table of
compiled ``strptime`` formats → ``dateutil`` as the last resort.  On typical
ISO-8601 input the fast path returns after one call.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Final

#: Supported aggregation windows, mapped to their duration.
WINDOWS: Final[dict[str, timedelta]] = {
    "1m": timedelta(minutes=1),
    "5m": timedelta(minutes=5),
    "15m": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "1d": timedelta(days=1),
}

#: DuckDB / SQL interval equivalents for the same windows.
WINDOW_SQL: Final[dict[str, str]] = {
    "1m": "1 minute",
    "5m": "5 minutes",
    "15m": "15 minutes",
    "1h": "1 hour",
    "6h": "6 hours",
    "1d": "1 day",
}

_STRPTIME_FORMATS: Final[tuple[str, ...]] = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%d/%b/%Y:%H:%M:%S %z",  # Apache / Nginx common log format
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",  # syslog (year-less)
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d",
    "%Y%m%dT%H%M%SZ",
)

_EPOCH_RE: Final[re.Pattern[str]] = re.compile(r"^\d{9,19}(?:\.\d{1,9})?$")

#: Sanity bounds.  A value outside these is a parse artefact (e.g. a port
#: number read as an epoch), not a real timestamp.
MIN_TIMESTAMP: Final[datetime] = datetime(1990, 1, 1, tzinfo=UTC)
MAX_TIMESTAMP: Final[datetime] = datetime(2100, 1, 1, tzinfo=UTC)


def utcnow() -> datetime:
    """Current time as an aware UTC datetime."""
    return datetime.now(UTC)


def ensure_utc(value: datetime, *, assume: str = "utc") -> datetime:
    """Return an aware UTC datetime.

    A naive input is interpreted per ``assume`` (``"utc"`` or ``"local"``).
    Defaulting to UTC is the safe choice: it is wrong by a fixed, documented
    offset rather than by whatever the host happens to be configured to.
    """
    if value.tzinfo is None:
        if assume == "local":
            return value.astimezone().astimezone(UTC)
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _from_epoch(raw: str) -> datetime | None:
    """Interpret a numeric string as s / ms / µs / ns since the epoch."""
    try:
        number = float(raw)
    except ValueError:
        return None
    digits = len(raw.split(".", 1)[0])
    if digits <= 10:
        seconds = number
    elif digits <= 13:
        seconds = number / 1_000
    elif digits <= 16:
        seconds = number / 1_000_000
    else:
        seconds = number / 1_000_000_000
    try:
        candidate = datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return candidate


def parse_timestamp(
    raw: str | int | float | datetime | None,
    *,
    assume: str = "utc",
    default_year: int | None = None,
) -> datetime | None:
    """Best-effort parse of an arbitrary timestamp representation.

    Returns ``None`` instead of raising: a bad timestamp is a per-record
    validation failure that belongs in the dead-letter queue, not an exception
    that aborts a ten-million-line job.
    """
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return _bounded(ensure_utc(raw, assume=assume))
    if isinstance(raw, (int, float)):
        return _bounded(_from_epoch(repr(raw)))

    text = raw.strip()
    if not text:
        return None
    # Nginx/Apache wrap the timestamp in brackets.
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]

    if _EPOCH_RE.match(text):
        parsed = _from_epoch(text)
        if parsed is not None:
            return _bounded(parsed)

    iso_candidate = text.replace("Z", "+00:00") if text.endswith("Z") else text
    try:
        return _bounded(ensure_utc(datetime.fromisoformat(iso_candidate), assume=assume))
    except ValueError:
        pass

    for fmt in _STRPTIME_FORMATS:
        try:
            parsed_dt = datetime.strptime(text, fmt)  # noqa: DTZ007 - tz handled below
        except ValueError:
            continue
        if parsed_dt.year == 1900 and "%Y" not in fmt:
            # Year-less syslog format: attribute it to the requested year.
            parsed_dt = parsed_dt.replace(year=default_year or utcnow().year)
        return _bounded(ensure_utc(parsed_dt, assume=assume))

    try:  # last resort — flexible but ~50x slower than the paths above
        from dateutil import parser as dateutil_parser

        return _bounded(ensure_utc(dateutil_parser.parse(text), assume=assume))
    except Exception:  # noqa: BLE001 - any dateutil failure means "unparseable"
        return None


def _bounded(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if not (MIN_TIMESTAMP <= value <= MAX_TIMESTAMP):
        return None
    return value


def floor_to_window(moment: datetime, window: str) -> datetime:
    """Truncate ``moment`` down to the start of its ``window`` bucket."""
    delta = WINDOWS.get(window)
    if delta is None:
        raise KeyError(f"unsupported window {window!r}; choose from {sorted(WINDOWS)}")
    moment = ensure_utc(moment)
    if window == "1d":
        return moment.replace(hour=0, minute=0, second=0, microsecond=0)
    seconds = int(delta.total_seconds())
    day_start = moment.replace(hour=0, minute=0, second=0, microsecond=0)
    elapsed = int((moment - day_start).total_seconds())
    return day_start + timedelta(seconds=elapsed - (elapsed % seconds))


def window_seconds(window: str) -> int:
    delta = WINDOWS.get(window)
    if delta is None:
        raise KeyError(f"unsupported window {window!r}")
    return int(delta.total_seconds())


def iter_windows(start: datetime, end: datetime, window: str) -> list[datetime]:
    """Every bucket start between ``start`` and ``end`` inclusive.

    Used to fill gaps: a time-series with missing buckets makes an outage look
    like a period of perfect health.
    """
    delta = WINDOWS[window]
    current = floor_to_window(start, window)
    stop = floor_to_window(end, window)
    out: list[datetime] = []
    while current <= stop:
        out.append(current)
        current += delta
    return out


def partition_values(moment: datetime) -> dict[str, str]:
    """Hive-style partition key/values for a timestamp."""
    moment = ensure_utc(moment)
    return {
        "year": f"{moment.year:04d}",
        "month": f"{moment.month:02d}",
        "day": f"{moment.day:02d}",
        "hour": f"{moment.hour:02d}",
    }


def to_iso(moment: datetime) -> str:
    """Canonical serialisation: UTC, second precision, trailing ``Z``."""
    return ensure_utc(moment).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_range(
    start: str | datetime | None,
    end: str | datetime | None,
    *,
    default_span: timedelta = timedelta(days=1),
) -> tuple[datetime, datetime]:
    """Normalise an optional ``(start, end)`` pair into a concrete UTC range."""
    parsed_end = parse_timestamp(end) or utcnow()
    parsed_start = parse_timestamp(start) or (parsed_end - default_span)
    if parsed_start > parsed_end:
        parsed_start, parsed_end = parsed_end, parsed_start
    return parsed_start, parsed_end


__all__ = [
    "MAX_TIMESTAMP",
    "MIN_TIMESTAMP",
    "WINDOWS",
    "WINDOW_SQL",
    "ensure_utc",
    "floor_to_window",
    "iter_windows",
    "parse_range",
    "parse_timestamp",
    "partition_values",
    "to_iso",
    "utcnow",
    "window_seconds",
]
