"""Structured application logging.

Responsibility
--------------
Emit one JSON object per application event containing ``timestamp, level,
service, module, function, request_id, duration, status, error`` — the exact
fields an operator needs to correlate a failure across API → worker → storage.

Security considerations
-----------------------
* A :class:`MaskingFilter` sits on the **handler**, not the logger, so *every*
  record — including ones emitted by third-party libraries such as uvicorn or
  SQLAlchemy — is redacted before it is written.
* Exception tracebacks are masked too.  A stack trace that includes a DSN with
  an embedded password is the classic leak; formatting happens before masking
  precisely to catch it.
* ``request_id`` is propagated through a :class:`~contextvars.ContextVar`, which
  is correct under both asyncio and threads (unlike a module global).
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from app.core.masking import Masker, default_masker

#: Correlation id for the current request / job / batch.
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
#: Arbitrary key/values merged into every record emitted in this context.
log_context_var: ContextVar[Mapping[str, Any] | None] = ContextVar("log_context", default=None)

_RESERVED = frozenset(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {
    "message",
    "asctime",
    "taskName",
}

_configured = False


def new_request_id() -> str:
    return uuid.uuid4().hex


def set_request_id(value: str | None = None) -> str:
    rid = value or new_request_id()
    request_id_var.set(rid)
    return rid


@contextmanager
def log_context(**fields: Any) -> Iterator[None]:
    """Attach ``fields`` to every log record emitted inside the block."""
    current = dict(log_context_var.get() or {})
    current.update(fields)
    token = log_context_var.set(current)
    try:
        yield
    finally:
        log_context_var.reset(token)


class MaskingFilter(logging.Filter):
    """Redacts secrets from the message, args and exception text."""

    def __init__(self, masker: Masker | None = None) -> None:
        super().__init__()
        self._masker = masker or default_masker

    def filter(self, record: logging.LogRecord) -> bool:
        if not self._masker.enabled:
            return True
        try:
            # Render once here so args-interpolation cannot re-introduce a
            # secret after masking.
            record.msg = self._masker.mask_text(record.getMessage())
            record.args = None
        except Exception:  # noqa: BLE001 - logging must never raise
            record.msg = "<unrenderable log message>"
            record.args = None
        if record.exc_info:
            formatted = logging.Formatter().formatException(record.exc_info)
            record.exc_text = self._masker.mask_text(formatted)
            record.exc_info = None
        for key, value in list(record.__dict__.items()):
            if key not in _RESERVED and isinstance(value, (str, dict, list)):
                record.__dict__[key] = self._masker.mask_object(value)
        return True


class ContextFilter(logging.Filter):
    """Injects service name, request id and contextual fields."""

    def __init__(self, service: str) -> None:
        super().__init__()
        self._service = service

    def filter(self, record: logging.LogRecord) -> bool:
        record.service = getattr(record, "service", self._service)
        record.request_id = getattr(record, "request_id", None) or request_id_var.get()
        extra = log_context_var.get()
        if extra:
            for key, value in extra.items():
                if key not in record.__dict__:
                    record.__dict__[key] = value
        return True


class JsonFormatter(logging.Formatter):
    """One compact JSON object per record."""

    def __init__(self, *, include_caller: bool = True) -> None:
        super().__init__()
        self._include_caller = include_caller

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "service": getattr(record, "service", "log-analytics"),
            "logger": record.name,
            "message": record.getMessage(),
        }
        if self._include_caller:
            payload["module"] = record.module
            payload["function"] = record.funcName
            payload["line"] = record.lineno
        request_id = getattr(record, "request_id", None)
        if request_id:
            payload["request_id"] = request_id
        for key, value in record.__dict__.items():
            if key in _RESERVED or key in payload or key.startswith("_"):
                continue
            payload[key] = value
        if record.exc_text:
            payload["error"] = record.exc_text
        try:
            return json.dumps(payload, default=str, ensure_ascii=False)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return json.dumps({"level": record.levelname, "message": str(record.msg)})


class ConsoleFormatter(logging.Formatter):
    """Human-friendly single-line output for local development."""

    _COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[1;31m",
    }
    _RESET = "\033[0m"

    def __init__(self, *, color: bool = True) -> None:
        super().__init__(datefmt="%H:%M:%S")
        self._color = color and sys.stderr.isatty()

    def format(self, record: logging.LogRecord) -> str:
        level = record.levelname
        prefix = (
            f"{self._COLORS.get(level, '')}{level:<8}{self._RESET}"
            if self._color
            else f"{level:<8}"
        )
        stamp = self.formatTime(record, self.datefmt)
        rid = getattr(record, "request_id", None)
        suffix = f" [{rid[:8]}]" if rid else ""
        line = f"{stamp} {prefix} {record.name}{suffix}: {record.getMessage()}"
        if record.exc_text:
            line = f"{line}\n{record.exc_text}"
        return line


def configure_logging(
    *,
    level: str = "INFO",
    fmt: str = "json",
    service: str = "log-analytics",
    log_file: Path | None = None,
    max_file_bytes: int = 10 * 1024**2,
    backup_count: int = 5,
    include_caller: bool = True,
    masker: Masker | None = None,
    force: bool = False,
) -> None:
    """Install the platform's logging configuration on the root logger.

    Idempotent: calling it twice (CLI then API) will not duplicate handlers.
    Logs go to **stderr** so that CLI commands can emit machine-readable
    results on stdout without interleaving.
    """
    global _configured
    root = logging.getLogger()
    if _configured and not force:
        root.setLevel(level.upper())
        return

    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()

    formatter: logging.Formatter = (
        JsonFormatter(include_caller=include_caller) if fmt == "json" else ConsoleFormatter()
    )
    masking = MaskingFilter(masker)
    context = ContextFilter(service)

    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(formatter)
    stream.addFilter(context)
    stream.addFilter(masking)
    root.addHandler(stream)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_file_bytes, backupCount=backup_count, encoding="utf-8"
        )
        file_handler.setFormatter(JsonFormatter(include_caller=include_caller))
        file_handler.addFilter(context)
        file_handler.addFilter(masking)
        root.addHandler(file_handler)

    root.setLevel(level.upper())
    # These libraries are chatty at INFO and their messages carry payloads.
    for noisy in ("urllib3", "botocore", "asyncio", "charset_normalizer", "fsspec"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _configured = True


def configure_from_settings(settings: Any) -> None:
    """Convenience wrapper driven by :class:`app.core.config.Settings`."""
    obs = settings.observability
    configure_logging(
        level=obs.level,
        fmt=obs.format,
        service=obs.service_name,
        log_file=obs.file,
        max_file_bytes=obs.max_file_bytes,
        backup_count=obs.backup_count,
        include_caller=obs.include_caller,
        masker=Masker(
            rules=settings.masking.rules,
            extra_field_names=settings.masking.extra_fields,
            enabled=settings.masking.enabled,
        ),
        force=True,
    )


def get_logger(name: str) -> logging.Logger:
    """Module-level logger accessor (``log = get_logger(__name__)``)."""
    return logging.getLogger(name)


@contextmanager
def timed_operation(
    logger: logging.Logger, operation: str, level: int = logging.INFO, **fields: Any
) -> Iterator[dict[str, Any]]:
    """Log the start/end of an operation with its duration and status.

    The yielded dict can be mutated by the block to attach result fields
    (record counts, byte totals) to the completion event.
    """
    started = time.perf_counter()
    result: dict[str, Any] = {}
    logger.log(level, "%s started", operation, extra={"operation": operation, **fields})
    try:
        yield result
    except Exception as exc:
        logger.exception(
            "%s failed",
            operation,
            extra={
                "operation": operation,
                "status": "error",
                "duration": round(time.perf_counter() - started, 6),
                "error_type": type(exc).__name__,
                **fields,
            },
        )
        raise
    else:
        logger.log(
            level,
            "%s completed",
            operation,
            extra={
                "operation": operation,
                "status": "ok",
                "duration": round(time.perf_counter() - started, 6),
                **fields,
                **result,
            },
        )


__all__ = [
    "ConsoleFormatter",
    "ContextFilter",
    "JsonFormatter",
    "MaskingFilter",
    "configure_from_settings",
    "configure_logging",
    "get_logger",
    "log_context",
    "new_request_id",
    "request_id_var",
    "set_request_id",
    "timed_operation",
]
