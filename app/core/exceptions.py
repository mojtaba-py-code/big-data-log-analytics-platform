"""Exception hierarchy for the platform.

Design rules
------------
* Every failure raised by the platform derives from :class:`LogAnalyticsError`
  so callers can catch one base class at process boundaries.
* Exceptions carry structured ``context`` instead of embedding values in the
  message.  That keeps messages stable for log aggregation *and* lets the
  masking layer redact the context before it reaches an operator's screen.
* ``public_message`` is what an HTTP client is allowed to see.  Internal detail
  (file paths, SQL, credentials) never crosses that boundary.
"""

from __future__ import annotations

from typing import Any


class LogAnalyticsError(Exception):
    """Base class for every error raised by this platform."""

    #: Message safe to return to an untrusted API client.
    public_message: str = "An internal error occurred."
    #: Stable machine-readable code, used by the API error envelope.
    code: str = "internal_error"

    def __init__(self, message: str | None = None, **context: Any) -> None:
        self.context: dict[str, Any] = context
        super().__init__(message or self.public_message)

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": str(self), "context": self.context}


# --------------------------------------------------------------------------- #
# Configuration / bootstrap
# --------------------------------------------------------------------------- #
class ConfigurationError(LogAnalyticsError):
    public_message = "The platform is misconfigured."
    code = "configuration_error"


class PluginNotFoundError(LogAnalyticsError):
    public_message = "The requested component is not registered."
    code = "plugin_not_found"


# --------------------------------------------------------------------------- #
# Security
# --------------------------------------------------------------------------- #
class SecurityError(LogAnalyticsError):
    public_message = "The request was rejected by a security control."
    code = "security_error"


class PathTraversalError(SecurityError):
    public_message = "The requested path is outside of the permitted roots."
    code = "path_traversal"


class AuthenticationError(SecurityError):
    public_message = "Authentication failed."
    code = "unauthenticated"


class AuthorizationError(SecurityError):
    public_message = "Insufficient privileges for this operation."
    code = "forbidden"


class RateLimitExceededError(SecurityError):
    public_message = "Rate limit exceeded."
    code = "rate_limited"

    def __init__(self, message: str | None = None, retry_after: int = 1, **context: Any) -> None:
        super().__init__(message, retry_after=retry_after, **context)
        self.retry_after = retry_after


# --------------------------------------------------------------------------- #
# Pipeline stages
# --------------------------------------------------------------------------- #
class PipelineError(LogAnalyticsError):
    public_message = "Processing failed."
    code = "pipeline_error"


class IngestionError(PipelineError):
    public_message = "The source could not be read."
    code = "ingestion_error"


class ParseError(PipelineError):
    """Raised for a *single* record that cannot be parsed.

    This is an expected, per-record condition: the pipeline routes the record
    to the dead-letter queue and keeps going.  It is never fatal.
    """

    public_message = "The record could not be parsed."
    code = "parse_error"


class StorageError(PipelineError):
    public_message = "The storage backend reported an error."
    code = "storage_error"


class QueryError(LogAnalyticsError):
    public_message = "The query could not be executed."
    code = "query_error"


class SearchSyntaxError(QueryError):
    """The user-supplied search expression is malformed.

    Unlike most errors, the message *is* safe to echo back: the parser only
    ever reports on the client's own input, never on server internals.
    """

    public_message = "Invalid search expression."
    code = "search_syntax_error"

    def __init__(self, message: str, **context: Any) -> None:
        super().__init__(message, **context)
        self.public_message = message


class JobError(LogAnalyticsError):
    public_message = "The background job failed."
    code = "job_error"


class RetryExhaustedError(LogAnalyticsError):
    public_message = "The operation failed after exhausting all retries."
    code = "retry_exhausted"


__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "ConfigurationError",
    "IngestionError",
    "JobError",
    "LogAnalyticsError",
    "ParseError",
    "PathTraversalError",
    "PipelineError",
    "PluginNotFoundError",
    "QueryError",
    "RateLimitExceededError",
    "RetryExhaustedError",
    "SearchSyntaxError",
    "SecurityError",
    "StorageError",
]
