"""Ingestion layer: pluggable sources of raw records."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.ingestion.base import LogSource, RawRecord, SourceStats, source_registry
from app.ingestion.database import DatabaseSource
from app.ingestion.files import (
    CsvFileSource,
    DirectorySource,
    FileSource,
    JsonArrayFileSource,
    open_file_source,
)
from app.ingestion.http_api import ApiSource, assert_url_allowed


def build_source(target: str | Path, settings: Settings, **kwargs: Any) -> LogSource:
    """Create the right source for ``target``.

    Dispatch is by *shape*, not by a flag the caller has to remember:
    an ``http(s)://`` string is an API, a ``dialect://`` string is a database,
    a directory is a directory, anything else is a file.
    """
    text = str(target)
    lowered = text.lower()
    roots = settings.ingest_roots()

    if lowered.startswith(("http://", "https://")):
        return ApiSource(
            text,
            timeout_seconds=settings.ingestion.http_timeout_seconds,
            max_bytes=settings.ingestion.http_max_bytes,
            allow_private=settings.ingestion.allow_private_network_sources,
            **kwargs,
        )
    if "://" in text and not lowered.startswith("file://"):
        return DatabaseSource(text, fetch_size=settings.ingestion.db_fetch_size, **kwargs)

    path = Path(text[7:] if lowered.startswith("file://") else text).expanduser()
    common: dict[str, Any] = {
        "allowed_roots": roots,
        "encoding": settings.processing.encoding,
        "encoding_errors": settings.processing.encoding_errors,
        "max_line_bytes": settings.processing.max_line_bytes,
        "max_bytes": settings.processing.max_file_bytes,
    }
    if path.is_dir():
        return DirectorySource(
            path,
            allowed_roots=roots,
            follow_symlinks=settings.ingestion.follow_symlinks,
            **{k: v for k, v in common.items() if k != "allowed_roots"},
            **kwargs,
        )
    return open_file_source(path, **common, **kwargs)


__all__ = [
    "ApiSource",
    "CsvFileSource",
    "DatabaseSource",
    "DirectorySource",
    "FileSource",
    "JsonArrayFileSource",
    "LogSource",
    "RawRecord",
    "SourceStats",
    "assert_url_allowed",
    "build_source",
    "open_file_source",
    "source_registry",
]
