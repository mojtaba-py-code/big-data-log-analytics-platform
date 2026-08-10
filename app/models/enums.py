"""Enumerations shared across the pipeline.

Using ``str``-backed enums means a value is JSON-serialisable, comparable to a
plain string and usable as a Parquet dictionary key without conversion code at
every boundary.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class LogLevel(StrEnum):
    """Canonical severity ladder.

    Different ecosystems spell severity differently (``WARN`` vs ``WARNING``,
    syslog's ``EMERG``, Nginx's ``crit``).  :meth:`coerce` folds all of them
    into this one ladder so ``level >= ERROR`` means the same thing regardless
    of which application produced the record.
    """

    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    ALERT = "ALERT"
    EMERGENCY = "EMERGENCY"
    UNKNOWN = "UNKNOWN"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]

    @property
    def is_error(self) -> bool:
        """True for anything an on-call engineer would count as a failure."""
        return self.severity >= _SEVERITY[LogLevel.ERROR]

    @classmethod
    def coerce(cls, value: object) -> LogLevel:
        if isinstance(value, cls):
            return value
        if value is None:
            return cls.UNKNOWN
        text = str(value).strip().upper()
        if not text:
            return cls.UNKNOWN
        if text in cls.__members__:
            return cls[text]
        return _ALIASES.get(text, cls.UNKNOWN)


_SEVERITY: Final[dict[LogLevel, int]] = {
    LogLevel.TRACE: 5,
    LogLevel.DEBUG: 10,
    LogLevel.INFO: 20,
    LogLevel.NOTICE: 25,
    LogLevel.WARNING: 30,
    LogLevel.ERROR: 40,
    LogLevel.CRITICAL: 50,
    LogLevel.ALERT: 60,
    LogLevel.EMERGENCY: 70,
    LogLevel.UNKNOWN: 0,
}

_ALIASES: Final[dict[str, LogLevel]] = {
    "WARN": LogLevel.WARNING,
    "WARNINGS": LogLevel.WARNING,
    "ERR": LogLevel.ERROR,
    "ERRORS": LogLevel.ERROR,
    "FATAL": LogLevel.CRITICAL,
    "CRIT": LogLevel.CRITICAL,
    "SEVERE": LogLevel.CRITICAL,
    "EMERG": LogLevel.EMERGENCY,
    "PANIC": LogLevel.EMERGENCY,
    "VERBOSE": LogLevel.DEBUG,
    "FINE": LogLevel.DEBUG,
    "FINEST": LogLevel.TRACE,
    "INFORMATION": LogLevel.INFO,
    "INFORMATIONAL": LogLevel.INFO,
    "NOTIFY": LogLevel.NOTICE,
    # syslog numeric priorities
    "0": LogLevel.EMERGENCY,
    "1": LogLevel.ALERT,
    "2": LogLevel.CRITICAL,
    "3": LogLevel.ERROR,
    "4": LogLevel.WARNING,
    "5": LogLevel.NOTICE,
    "6": LogLevel.INFO,
    "7": LogLevel.DEBUG,
}


class HttpMethod(StrEnum):
    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    CONNECT = "CONNECT"
    OTHER = "OTHER"

    @classmethod
    def coerce(cls, value: object) -> HttpMethod | None:
        if value is None:
            return None
        if isinstance(value, cls):
            return value
        text = str(value).strip().upper()
        if not text:
            return None
        return cls.__members__.get(text, cls.OTHER)


class Environment(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    UNKNOWN = "unknown"


class SourceType(StrEnum):
    """Where a record entered the platform from."""

    FILE = "file"
    DIRECTORY = "directory"
    DATABASE = "database"
    API = "api"
    STREAM = "stream"
    SYNTHETIC = "synthetic"
    UNKNOWN = "unknown"


class RejectReason(StrEnum):
    """Why a record landed in the dead-letter queue.

    A closed vocabulary matters: these values are the labels on the rejection
    counters, and free-text reasons make that dashboard useless.
    """

    UNPARSEABLE = "unparseable"
    EMPTY_LINE = "empty_line"
    LINE_TOO_LONG = "line_too_long"
    ENCODING_ERROR = "encoding_error"
    MISSING_TIMESTAMP = "missing_timestamp"
    INVALID_TIMESTAMP = "invalid_timestamp"
    TIMESTAMP_OUT_OF_RANGE = "timestamp_out_of_range"
    MISSING_MESSAGE = "missing_message"
    MESSAGE_TOO_LONG = "message_too_long"
    INVALID_IP = "invalid_ip"
    INVALID_STATUS_CODE = "invalid_status_code"
    INVALID_LEVEL = "invalid_level"
    INVALID_RESPONSE_TIME = "invalid_response_time"
    SCHEMA_VIOLATION = "schema_violation"
    DUPLICATE = "duplicate"
    TRANSFORM_ERROR = "transform_error"
    STORAGE_ERROR = "storage_error"
    UNKNOWN = "unknown"


class AnomalyType(StrEnum):
    ERROR_SPIKE = "error_spike"
    TRAFFIC_SPIKE = "traffic_spike"
    TRAFFIC_DROP = "traffic_drop"
    LATENCY_SPIKE = "latency_spike"
    SERVER_ERROR_SURGE = "server_error_surge"
    UNUSUAL_PATTERN = "unusual_pattern"
    SUSPICIOUS_IP = "suspicious_ip"


class Severity(StrEnum):
    """Severity of an anomaly or security finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: float) -> Severity:
        """Map a 0-100 risk score onto the ladder."""
        if score >= 90:
            return cls.CRITICAL
        if score >= 70:
            return cls.HIGH
        if score >= 45:
            return cls.MEDIUM
        if score >= 20:
            return cls.LOW
        return cls.INFO


class SecurityFindingType(StrEnum):
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    ENDPOINT_SCANNING = "endpoint_scanning"
    SENSITIVE_ENDPOINT_ACCESS = "sensitive_endpoint_access"
    SUSPICIOUS_USER_AGENT = "suspicious_user_agent"
    REQUEST_FLOOD = "request_flood"
    SECRET_IN_LOG = "secret_in_log"  # noqa: S105 - a finding name, not a credential  # nosec B105
    ANOMALOUS_ERROR_RATE = "anomalous_error_rate"


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"

    @property
    def is_terminal(self) -> bool:
        return self in {JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED}


class DataLayer(StrEnum):
    """Medallion-style storage layers."""

    RAW = "raw"
    PROCESSED = "processed"
    ANALYTICS = "analytics"
    REJECTED = "rejected"


__all__ = [
    "AnomalyType",
    "DataLayer",
    "Environment",
    "HttpMethod",
    "JobStatus",
    "LogLevel",
    "RejectReason",
    "SecurityFindingType",
    "Severity",
    "SourceType",
]
