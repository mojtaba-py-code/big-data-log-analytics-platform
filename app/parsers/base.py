"""Parser interface and shared field-mapping helpers.

Responsibility
--------------
A parser turns one raw line (or one already-structured record) into a
:class:`~app.models.log_event.LogEvent`.  It does **not** validate business
rules, deduplicate, or write anything — those are separate stages.

Interface contract
------------------
``can_parse(sample)``
    Cheap heuristic used by the format detector.  Must never raise.
``parse(raw, context)``
    Returns a ``LogEvent`` or raises :class:`~app.core.exceptions.ParseError`.
    Raising is normal and expected: the caller dead-letters that one line.
``confidence``
    Tie-breaker when several parsers accept the same sample.  Specific formats
    (JSON, Apache combined) outrank the catch-all plain-text parser.

Security considerations
-----------------------
* Every regex here is bounded.  Log lines are attacker-influenced input, and an
  unbounded ``(.*)+`` in a parser is a catastrophic-backtracking DoS.
* Parsers never ``eval``/``exec`` and never import by name from data.
* Field values are length-capped by the :class:`LogEvent` schema itself, so a
  10 MB "user agent" cannot propagate into storage.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, ClassVar, Final

from app.core.registry import Registry
from app.core.timeutil import parse_timestamp, utcnow
from app.models.enums import Environment, HttpMethod, LogLevel, SourceType
from app.models.log_event import LogEvent


@dataclass(slots=True)
class ParseContext:
    """Everything a parser needs to know about *where* a line came from.

    Defaults flow from the source (a file named ``payment-api.log`` sets
    ``default_service='payment-api'``), so records keep their provenance even
    when the format itself carries none.
    """

    source: str = "unknown"
    source_type: SourceType = SourceType.UNKNOWN
    default_service: str | None = None
    default_hostname: str | None = None
    environment: Environment = Environment.UNKNOWN
    line_number: int | None = None
    keep_raw: bool = True
    #: Year to assume for formats that omit it (syslog).
    default_year: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class LogParser(ABC):
    """Base class for all parsers."""

    #: Registry name; set by the ``@parser_registry.register`` decorator.
    name: ClassVar[str] = "base"
    #: Detector tie-breaker, higher wins.
    confidence: ClassVar[int] = 0
    #: File extensions this parser is a natural fit for.
    extensions: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    def can_parse(self, sample: Sequence[str]) -> bool:
        """Heuristically decide whether this parser understands ``sample``."""

    @abstractmethod
    def parse(self, raw: str, context: ParseContext) -> LogEvent:
        """Parse one record or raise :class:`ParseError`."""

    # -- shared helpers ---------------------------------------------------- #
    def _finalize(
        self,
        fields: dict[str, Any],
        raw: str,
        context: ParseContext,
    ) -> LogEvent:
        """Apply context defaults and build the event.

        Centralised so every parser produces identically-shaped records: the
        normalisation stage downstream should never have to special-case which
        parser a record came from.
        """
        fields.setdefault("source", context.source)
        fields.setdefault("source_type", context.source_type)
        if not fields.get("service") and context.default_service:
            fields["service"] = context.default_service
        if not fields.get("hostname") and context.default_hostname:
            fields["hostname"] = context.default_hostname
        fields.setdefault("environment", context.environment)
        fields.setdefault("parser", self.name)
        if "timestamp" not in fields or fields["timestamp"] is None:
            # A record with no clock is still data; validation decides its
            # fate. Stamping ingest time keeps it partitionable meanwhile.
            fields["timestamp"] = utcnow()
            fields.setdefault("metadata", {})["timestamp_inferred"] = True
        fields["raw_message"] = raw if context.keep_raw else ""
        return LogEvent.build(**fields)


# --------------------------------------------------------------------------- #
# Field mapping shared by structured parsers (JSON, CSV, database rows)
# --------------------------------------------------------------------------- #
#: Canonical field → accepted source keys, lower-cased.  Ordered by preference.
FIELD_ALIASES: Final[dict[str, tuple[str, ...]]] = {
    "timestamp": (
        "timestamp",
        "time",
        "@timestamp",
        "ts",
        "datetime",
        "date",
        "eventtime",
        "event_time",
        "asctime",
        "created",
        "created_at",
        "logged_at",
        "_time",
    ),
    "level": (
        "level",
        "severity",
        "levelname",
        "log_level",
        "loglevel",
        "priority",
        "status_level",
        "lvl",
        "level_name",
    ),
    "message": (
        "message",
        "msg",
        "text",
        "body",
        "event",
        "description",
        "log",
        "detail",
        "short_message",
        "content",
    ),
    "service": (
        "service",
        "service_name",
        "app",
        "application",
        "component",
        "container_name",
        "kubernetes_container_name",
        "program",
        "unit",
        "job",
    ),
    "hostname": ("hostname", "host", "server", "node", "machine", "instance", "pod"),
    "environment": ("environment", "env", "stage", "deployment_env"),
    "logger": ("logger", "logger_name", "channel", "category", "source_module", "module"),
    "ip_address": (
        "ip",
        "ip_address",
        "client_ip",
        "remote_addr",
        "remote_ip",
        "src_ip",
        "source_ip",
        "x_forwarded_for",
        "clientip",
        "caller_ip",
    ),
    "user_id": ("user_id", "user", "username", "uid", "account_id", "actor", "subject"),
    "request_id": (
        "request_id",
        "req_id",
        "correlation_id",
        "trace_id",
        "x_request_id",
        "traceid",
        "span_id",
    ),
    "http_method": ("method", "http_method", "verb", "request_method"),
    "endpoint": ("path", "endpoint", "url", "uri", "route", "request_uri", "request_path"),
    "status_code": ("status", "status_code", "http_status", "response_code", "code"),
    "response_time_ms": (
        "response_time",
        "response_time_ms",
        "duration",
        "duration_ms",
        "latency",
        "latency_ms",
        "elapsed",
        "elapsed_ms",
        "took",
        "request_time",
        "upstream_time",
    ),
    "bytes_sent": (
        "bytes",
        "bytes_sent",
        "size",
        "content_length",
        "response_size",
        "body_bytes_sent",
    ),
    "user_agent": ("user_agent", "useragent", "http_user_agent", "ua", "agent"),
    "referrer": ("referrer", "referer", "http_referer", "http_referrer"),
}

#: Reverse index built once: source key → canonical field.
_ALIAS_INDEX: Final[dict[str, str]] = {
    alias: canonical for canonical, aliases in FIELD_ALIASES.items() for alias in aliases
}

_NORMALISE_KEY: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9]+")
_CAMEL_BOUNDARY: Final[re.Pattern[str]] = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

#: Duration units → multiplier to milliseconds.
_DURATION_UNITS: Final[dict[str, float]] = {
    "ns": 1e-6,
    "us": 1e-3,
    "µs": 1e-3,
    "ms": 1.0,
    "s": 1000.0,
    "sec": 1000.0,
    "secs": 1000.0,
    "second": 1000.0,
    "seconds": 1000.0,
    "m": 60_000.0,
    "min": 60_000.0,
}

_DURATION_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*([0-9]{1,15}(?:\.[0-9]{1,9})?)\s*([a-zµ]{0,7})\s*$", re.IGNORECASE
)


@lru_cache(maxsize=4_096)
def normalise_key(key: str) -> str:
    """``X-Request-ID`` / ``request.id`` / ``requestId`` → ``request_id``.

    Cached: a source emits the same handful of field names on every record, so
    this turns two regex passes per key per record into a dict lookup.  The
    cache is bounded, so a source with pathologically varied keys degrades to
    the uncached cost rather than growing without limit.
    """
    if key.islower() and key.isidentifier():
        return key  # already canonical - the common case
    # camelCase -> snake_case before punctuation folding.
    spaced = _CAMEL_BOUNDARY.sub("_", key)
    return _NORMALISE_KEY.sub("_", spaced.lower()).strip("_")


#: Field names whose unit is unambiguous, mapped to their multiplier to ms.
_DURATION_BY_NAME: Final[dict[str, float]] = {
    "request_time": 1_000.0,  # nginx $request_time is seconds
    "upstream_time": 1_000.0,
    "upstream_response_time": 1_000.0,
}

#: Suffix → multiplier to milliseconds.  Checked before any magnitude guess.
_DURATION_SUFFIXES: Final[tuple[tuple[str, float], ...]] = (
    ("_ms", 1.0),
    ("_millis", 1.0),
    ("_milliseconds", 1.0),
    ("_us", 0.001),
    ("_micros", 0.001),
    ("_ns", 1e-6),
    ("_nanos", 1e-6),
    ("_s", 1_000.0),
    ("_sec", 1_000.0),
    ("_secs", 1_000.0),
    ("_seconds", 1_000.0),
)


def duration_multiplier(field_name: str | None) -> float | None:
    """Multiplier to milliseconds implied by a field's *name*, if any.

    The name is far more reliable than the value: ``duration_ms=12.5`` is
    12.5 ms, and guessing from magnitude would turn it into 12.5 seconds — a
    1000x error that silently corrupts every latency percentile downstream.
    """
    if not field_name:
        return None
    name = field_name.lower()
    if name in _DURATION_BY_NAME:
        return _DURATION_BY_NAME[name]
    for suffix, multiplier in _DURATION_SUFFIXES:
        if name.endswith(suffix):
            return multiplier
    return None


def coerce_duration_ms(value: Any, field_name: str | None = None) -> float | None:
    """Convert a duration to milliseconds.

    Resolution order, most reliable first:

    1. An explicit unit in the *value* (``"12ms"``, ``"1.5s"``).
    2. The unit implied by the *field name* (``duration_ms``, ``request_time``).
    3. A magnitude heuristic, used only when both of the above are silent:
       a fractional value below 10 is treated as seconds (the shape emitted by
       Nginx and most HTTP client timers); everything else is milliseconds.

    Step 3 is a genuine guess and is documented as such — it is why the field
    name should be explicit wherever a log format is under your control.
    """
    if value is None or value == "" or value == "-":
        return None
    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        number = float(value)
    else:
        match = _DURATION_RE.match(str(value))
        if not match:
            return None
        number = float(match.group(1))
        unit = (match.group(2) or "").lower()
        if unit:
            multiplier = _DURATION_UNITS.get(unit)
            return number * multiplier if multiplier is not None else None

    by_name = duration_multiplier(field_name)
    if by_name is not None:
        return number * by_name
    if 0 < number < 10 and number != int(number):
        return number * 1_000.0
    return number


def coerce_int(value: Any) -> int | None:
    if value is None or value == "" or value == "-":
        return None
    if isinstance(value, bool):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def map_structured_record(
    record: Mapping[str, Any],
    *,
    extra_aliases: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Map an arbitrary structured record onto canonical field names.

    Unmapped keys are preserved in ``metadata`` — dropping them would lose the
    application-specific context that makes a log line useful.
    """
    mapped: dict[str, Any] = {}
    source_names: dict[str, str] = {}
    metadata: dict[str, Any] = {}
    custom = {normalise_key(k): v for k, v in (extra_aliases or {}).items()}

    for key, value in record.items():
        norm = normalise_key(str(key))
        canonical = custom.get(norm) or _ALIAS_INDEX.get(norm)
        if canonical is None or canonical in mapped:
            if value is not None and value != "":
                metadata[norm] = value
            continue
        mapped[canonical] = value
        # Remembered because the unit of a duration is carried by its *name*.
        source_names[canonical] = norm

    return _coerce_mapped(mapped, metadata, source_names)


def _coerce_mapped(
    mapped: dict[str, Any],
    metadata: dict[str, Any],
    source_names: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if "timestamp" in mapped:
        out["timestamp"] = parse_timestamp(mapped["timestamp"])
    if "level" in mapped:
        out["level"] = LogLevel.coerce(mapped["level"])
    for key in (
        "message",
        "service",
        "hostname",
        "logger",
        "user_id",
        "request_id",
        "ip_address",
        "endpoint",
        "user_agent",
        "referrer",
    ):
        value = mapped.get(key)
        if value is not None and value != "":
            out[key] = str(value)
    if "environment" in mapped:
        try:
            out["environment"] = Environment(str(mapped["environment"]).lower())
        except ValueError:
            metadata["environment_raw"] = mapped["environment"]
    if "http_method" in mapped:
        out["http_method"] = HttpMethod.coerce(mapped["http_method"])
    status = coerce_int(mapped.get("status_code"))
    if status is not None and 100 <= status <= 599:
        out["status_code"] = status
    elif status is not None:
        metadata["status_code_raw"] = status
    duration = coerce_duration_ms(
        mapped.get("response_time_ms"),
        (source_names or {}).get("response_time_ms"),
    )
    if duration is not None:
        out["response_time_ms"] = duration
    size = coerce_int(mapped.get("bytes_sent"))
    if size is not None and size >= 0:
        out["bytes_sent"] = size
    if metadata:
        out["metadata"] = metadata
    return out


#: Registry of every available parser.
parser_registry: Registry[LogParser] = Registry("parser")


__all__ = [
    "FIELD_ALIASES",
    "LogParser",
    "ParseContext",
    "coerce_duration_ms",
    "coerce_int",
    "duration_multiplier",
    "map_structured_record",
    "normalise_key",
    "parser_registry",
]
