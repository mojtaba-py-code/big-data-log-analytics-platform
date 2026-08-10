"""The canonical log record.

Every source, format and parser converges on :class:`LogEvent`.  Downstream
stages (validation, dedup, analytics, storage, search) know only this schema,
which is what lets a new parser be added without touching anything else.

Design decisions
----------------
* **Pydantic, not a bare dataclass.**  The schema is a trust boundary: records
  arrive from files, HTTP and databases.  Pydantic gives coercion, bounds
  checking and a JSON schema for the API in one declaration.
* **Everything except ``timestamp`` is optional.**  A plain-text application log
  has no ``status_code``; an Nginx access log has no ``logger``.  Forcing a
  union of all sources to be complete would reject most real input.
* **Validation is paid for deliberately.**  Constructing a validated event is
  the single most expensive step in the pipeline (see ``docs/PERFORMANCE.md``
  for the measured split).  It is kept because the alternative — trusting
  parser output — moves malformed data past the one place equipped to reject
  it.  :meth:`LogEvent.build` is the parser-facing constructor: it validates,
  and additionally folds unknown keys into ``metadata`` instead of raising.
* **``metadata`` is a bounded dict.**  Unmapped source fields are preserved
  (never silently dropped) but capped so a hostile source cannot blow up memory
  or the Parquet schema.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from typing import Annotated, Any, Final, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.hashing import event_id_for
from app.core.timeutil import ensure_utc, to_iso, utcnow
from app.models.enums import Environment, HttpMethod, LogLevel, SourceType

#: Caps that keep a single hostile record from becoming a memory problem.
MAX_METADATA_KEYS: Final[int] = 64
MAX_METADATA_VALUE_LENGTH: Final[int] = 4_096
MAX_MESSAGE_LENGTH: Final[int] = 65_536
MAX_RAW_LENGTH: Final[int] = 131_072

#: Field order used for the default content fingerprint.
DEFAULT_FINGERPRINT_FIELDS: Final[tuple[str, ...]] = (
    "timestamp",
    "service",
    "level",
    "message",
)

ShortStr = Annotated[str, Field(max_length=255)]


class LogEvent(BaseModel):
    """One normalised log record."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=False,
        use_enum_values=False,
        ser_json_timedelta="float",
    )

    # -- identity ---------------------------------------------------------- #
    event_id: str = Field(
        default="",
        max_length=64,
        description="Deterministic id; identical input always yields the same id.",
    )
    timestamp: datetime = Field(description="Event time, always timezone-aware UTC.")
    ingested_at: datetime = Field(default_factory=utcnow)

    # -- provenance -------------------------------------------------------- #
    source: ShortStr = Field(default="unknown", description="Origin of the record.")
    source_type: SourceType = SourceType.UNKNOWN
    service: ShortStr | None = None
    hostname: ShortStr | None = None
    environment: Environment = Environment.UNKNOWN

    # -- payload ----------------------------------------------------------- #
    level: LogLevel = LogLevel.UNKNOWN
    logger: ShortStr | None = None
    message: str = Field(default="", max_length=MAX_MESSAGE_LENGTH)

    # -- request context ---------------------------------------------------- #
    ip_address: ShortStr | None = None
    user_id: ShortStr | None = None
    request_id: ShortStr | None = None
    http_method: HttpMethod | None = None
    endpoint: Annotated[str, Field(max_length=2_048)] | None = None
    status_code: Annotated[int, Field(ge=100, le=599)] | None = None
    response_time_ms: Annotated[float, Field(ge=0, le=86_400_000)] | None = None
    bytes_sent: Annotated[int, Field(ge=0)] | None = None
    user_agent: Annotated[str, Field(max_length=1_024)] | None = None
    referrer: Annotated[str, Field(max_length=2_048)] | None = None

    # -- extras ------------------------------------------------------------- #
    metadata: dict[str, Any] = Field(default_factory=dict)
    raw_message: str = Field(default="", max_length=MAX_RAW_LENGTH)
    parser: ShortStr | None = None

    # -- validators --------------------------------------------------------- #
    @field_validator("timestamp", "ingested_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)

    @field_validator("level", mode="before")
    @classmethod
    def _level(cls, value: object) -> LogLevel:
        return LogLevel.coerce(value)

    @field_validator("http_method", mode="before")
    @classmethod
    def _method(cls, value: object) -> HttpMethod | None:
        return HttpMethod.coerce(value)

    @field_validator("ip_address", mode="before")
    @classmethod
    def _ip(cls, value: object) -> str | None:
        """Keep only syntactically valid addresses.

        An invalid value is dropped rather than raised on: the *validation*
        stage decides whether that is fatal, and it can then dead-letter the
        record with a precise reason instead of a Pydantic traceback.
        """
        if value is None or value == "":
            return None
        text = str(value).strip()
        if text in {"-", "unknown"}:
            return None
        # X-Forwarded-For style list: the left-most entry is the client.
        if "," in text:
            text = text.split(",", 1)[0].strip()
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return None

    @field_validator("metadata", mode="before")
    @classmethod
    def _bounded_metadata(cls, value: object) -> dict[str, Any]:
        if not value:
            return {}
        if not isinstance(value, dict):
            return {"value": str(value)[:MAX_METADATA_VALUE_LENGTH]}
        out: dict[str, Any] = {}
        for key, item in list(value.items())[:MAX_METADATA_KEYS]:
            name = str(key)[:128]
            if isinstance(item, str) and len(item) > MAX_METADATA_VALUE_LENGTH:
                item = item[:MAX_METADATA_VALUE_LENGTH]
            out[name] = item
        return out

    @model_validator(mode="after")
    def _assign_event_id(self) -> Self:
        if not self.event_id:
            object.__setattr__(self, "event_id", self.compute_event_id())
        return self

    # -- derived ------------------------------------------------------------ #
    def compute_event_id(self) -> str:
        """Deterministic id derived from the record's identifying content.

        ``ingested_at`` is deliberately excluded: including wall-clock time
        would make re-ingestion produce new ids and break idempotency.
        """
        return event_id_for(
            self.timestamp,
            self.source,
            self.service,
            self.level,
            self.message or self.raw_message,
            self.request_id,
        )

    @property
    def is_error(self) -> bool:
        """Error by severity *or* by HTTP status."""
        return self.level.is_error or (self.status_code is not None and self.status_code >= 500)

    @property
    def status_class(self) -> str | None:
        """``2xx``/``3xx``/``4xx``/``5xx`` bucket, or ``None``."""
        if self.status_code is None:
            return None
        return f"{self.status_code // 100}xx"

    @property
    def is_http(self) -> bool:
        return self.status_code is not None or self.http_method is not None

    def fingerprint_source(self, fields: tuple[str, ...] = DEFAULT_FINGERPRINT_FIELDS) -> list[Any]:
        """Values used by content-based de-duplication."""
        return [getattr(self, name, None) for name in fields]

    # -- serialisation ------------------------------------------------------ #
    def to_row(self) -> dict[str, Any]:
        """Flat, columnar-friendly dict for Parquet/DuckDB.

        ``metadata`` is serialised to a JSON string so the Parquet schema stays
        stable no matter which extra keys a source happens to emit — a varying
        struct schema is what breaks partitioned datasets at query time.
        """
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "ingested_at": self.ingested_at,
            "source": self.source,
            "source_type": str(self.source_type),
            "service": self.service,
            "hostname": self.hostname,
            "environment": str(self.environment),
            "level": str(self.level),
            "logger": self.logger,
            "message": self.message,
            "ip_address": self.ip_address,
            "user_id": self.user_id,
            "request_id": self.request_id,
            "http_method": str(self.http_method) if self.http_method else None,
            "endpoint": self.endpoint,
            "status_code": self.status_code,
            "response_time_ms": self.response_time_ms,
            "bytes_sent": self.bytes_sent,
            "user_agent": self.user_agent,
            "referrer": self.referrer,
            "metadata": json.dumps(self.metadata, default=str) if self.metadata else None,
            "raw_message": self.raw_message,
            "parser": self.parser,
        }

    def to_api_dict(self) -> dict[str, Any]:
        """JSON-safe representation for API responses."""
        row = self.to_row()
        row["timestamp"] = to_iso(self.timestamp)
        row["ingested_at"] = to_iso(self.ingested_at)
        row["metadata"] = self.metadata
        return row

    # -- construction -------------------------------------------------------- #
    @classmethod
    def build(cls, **fields: Any) -> LogEvent:
        """Validated constructor used by parsers.

        Unknown keys are folded into ``metadata`` instead of raising, so a
        parser that discovers an extra field in a custom format never loses it
        and never crashes the run.
        """
        known = cls.model_fields
        extras = {k: v for k, v in fields.items() if k not in known}
        if extras:
            merged = dict(fields.get("metadata") or {})
            merged.update(extras)
            fields = {k: v for k, v in fields.items() if k in known}
            fields["metadata"] = merged
        return cls(**fields)

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return f"{to_iso(self.timestamp)} {self.level} {self.service or '-'}: {self.message[:80]}"


#: Column order of :meth:`LogEvent.to_row`, reused by the storage layer.
LOG_EVENT_COLUMNS: Final[tuple[str, ...]] = (
    "event_id",
    "timestamp",
    "ingested_at",
    "source",
    "source_type",
    "service",
    "hostname",
    "environment",
    "level",
    "logger",
    "message",
    "ip_address",
    "user_id",
    "request_id",
    "http_method",
    "endpoint",
    "status_code",
    "response_time_ms",
    "bytes_sent",
    "user_agent",
    "referrer",
    "metadata",
    "raw_message",
    "parser",
)

#: Columns a client is allowed to filter, sort or search on.  Anything not in
#: this set is rejected by the search layer *before* it can reach SQL.
QUERYABLE_COLUMNS: Final[frozenset[str]] = frozenset(LOG_EVENT_COLUMNS) - {"metadata"}


__all__ = [
    "DEFAULT_FINGERPRINT_FIELDS",
    "LOG_EVENT_COLUMNS",
    "MAX_MESSAGE_LENGTH",
    "QUERYABLE_COLUMNS",
    "LogEvent",
]
