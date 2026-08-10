"""File and directory ingestion.

Supports ``.log``, ``.txt``, ``.csv``, ``.tsv``, ``.json``, ``.jsonl`` and any
of them gzipped (``.gz``).

Memory
------
Files are read line-by-line through a buffered text stream; a 40 GB log costs
the same resident memory as a 40 KB one.  Gzip is decompressed on the fly, and
the *decompressed* byte count is capped (``max_bytes``) so a compression bomb
cannot exhaust the disk or RAM.

Security
--------
* Every path is resolved through :func:`app.core.paths.resolve_within` against
  the configured ingest roots — a traversal or symlink escape fails before the
  file is opened.
* Lines longer than ``max_line_bytes`` are truncated and reported rather than
  buffered, so a single unterminated 2 GB "line" cannot OOM the process.
* Decoding uses ``errors="replace"`` by default: a corrupt byte sequence
  degrades one record instead of aborting the job.
"""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from app.core.exceptions import IngestionError
from app.core.logging import get_logger
from app.core.paths import iter_files, open_stream, resolve_within
from app.ingestion.base import LogSource, RawRecord, source_registry
from app.models.enums import SourceType

log = get_logger(__name__)

TEXT_EXTENSIONS = frozenset({".log", ".txt", ".out", ".jsonl", ".ndjson", ".json"})
TABULAR_EXTENSIONS = frozenset({".csv", ".tsv"})
DEFAULT_PATTERNS = ("*.log", "*.txt", "*.csv", "*.tsv", "*.json", "*.jsonl", "*.gz")


def _effective_suffix(path: Path) -> str:
    """Suffix ignoring a trailing ``.gz`` (``access.log.gz`` → ``.log``)."""
    if path.suffix.lower() == ".gz":
        return Path(path.stem).suffix.lower()
    return path.suffix.lower()


@source_registry.register("file")
class FileSource(LogSource):
    """Streams one file, line by line."""

    name = "file"
    source_type = SourceType.FILE

    def __init__(
        self,
        path: str | Path,
        *,
        allowed_roots: Sequence[Path] | None = None,
        encoding: str = "utf-8",
        encoding_errors: str = "replace",
        max_line_bytes: int = 1_048_576,
        max_bytes: int | None = None,
        skip_header: bool = False,
    ) -> None:
        super().__init__()
        self.path = (
            resolve_within(path, allowed_roots, must_exist=True)
            if allowed_roots
            else Path(path).expanduser().resolve()
        )
        if not self.path.is_file():
            raise IngestionError("source is not a regular file", path=str(self.path))
        self.encoding = encoding
        self.encoding_errors = encoding_errors
        self.max_line_bytes = max_line_bytes
        self.max_bytes = max_bytes
        self.skip_header = skip_header

    def describe(self) -> str:
        return str(self.path)

    def suggested_service(self) -> str | None:
        """Derive a service name from the filename (``payment-api.log``)."""
        stem = self.path.name
        for suffix in (".gz", ".log", ".txt", ".jsonl", ".json", ".csv", ".tsv", ".out"):
            if stem.lower().endswith(suffix):
                stem = stem[: -len(suffix)]
        stem = stem.rstrip(".-_")
        return stem or None

    def estimated_bytes(self) -> int | None:
        try:
            return self.path.stat().st_size
        except OSError:  # pragma: no cover - race with deletion
            return None

    def sample(self, count: int = 25) -> list[str]:
        lines: list[str] = []
        try:
            with open_stream(
                self.path,
                encoding=self.encoding,
                errors=self.encoding_errors,
                max_bytes=8 * 1024 * 1024,
            ) as stream:
                for line in stream:
                    if line.strip():
                        lines.append(line.rstrip("\r\n"))
                    if len(lines) >= count:
                        break
        except OSError as exc:
            raise IngestionError("failed to sample the source file") from exc
        return lines

    def read(self) -> Iterator[RawRecord]:
        source = str(self.path)
        try:
            stream = open_stream(
                self.path,
                encoding=self.encoding,
                errors=self.encoding_errors,
                max_bytes=self.max_bytes,
            )
        except OSError as exc:
            raise IngestionError("failed to open the source file") from exc

        with stream:
            for number, line in enumerate(stream, start=1):
                if number == 1 and self.skip_header:
                    continue
                stripped = line.rstrip("\r\n")
                size = len(line.encode(self.encoding, "ignore"))
                self.stats.bytes_read += size
                if not stripped.strip():
                    self.stats.skipped_empty += 1
                    continue
                if len(stripped) > self.max_line_bytes:
                    # Truncate rather than drop: the head of an oversized line
                    # usually still identifies what produced it.
                    self.stats.skipped_oversized += 1
                    stripped = stripped[: self.max_line_bytes]
                self.stats.records_read += 1
                yield RawRecord(payload=stripped, source=source, line_number=number, byte_size=size)


@source_registry.register("csv_file", "csv")
class CsvFileSource(LogSource):
    """Streams a delimited file, yielding one mapping per row.

    The dialect (delimiter, quoting) is sniffed from the header, so operators
    do not have to declare it — but it can be forced when sniffing guesses
    wrong on a file whose first line contains commas inside quotes.
    """

    name = "csv_file"
    source_type = SourceType.FILE

    def __init__(
        self,
        path: str | Path,
        *,
        allowed_roots: Sequence[Path] | None = None,
        delimiter: str | None = None,
        encoding: str = "utf-8",
        encoding_errors: str = "replace",
        max_bytes: int | None = None,
        max_field_size: int = 1_048_576,
    ) -> None:
        super().__init__()
        self.path = (
            resolve_within(path, allowed_roots, must_exist=True)
            if allowed_roots
            else Path(path).expanduser().resolve()
        )
        self.delimiter = delimiter
        self.encoding = encoding
        self.encoding_errors = encoding_errors
        self.max_bytes = max_bytes
        # csv's default field limit is 128 KB; raise it deliberately and
        # bounded, rather than letting a long field abort the whole file.
        csv.field_size_limit(max_field_size)

    def describe(self) -> str:
        return str(self.path)

    def suggested_service(self) -> str | None:
        return self.path.stem or None

    def estimated_bytes(self) -> int | None:
        try:
            return self.path.stat().st_size
        except OSError:  # pragma: no cover
            return None

    def sample(self, count: int = 25) -> list[str]:
        with open_stream(
            self.path, encoding=self.encoding, errors=self.encoding_errors, max_bytes=4_194_304
        ) as stream:
            return [line.rstrip("\r\n") for _, line in zip(range(count), stream, strict=False)]

    def _dialect(self, header_line: str) -> type[csv.Dialect] | csv.Dialect | str:
        if self.delimiter:

            class _Forced(csv.excel):
                delimiter = self.delimiter  # type: ignore[assignment]

            return _Forced
        try:
            return csv.Sniffer().sniff(header_line, delimiters=",;\t|")
        except csv.Error:
            log.debug("CSV dialect sniffing failed, falling back to excel")
            return csv.excel

    def read(self) -> Iterator[RawRecord]:
        source = str(self.path)
        with open_stream(
            self.path,
            encoding=self.encoding,
            errors=self.encoding_errors,
            max_bytes=self.max_bytes,
        ) as stream:
            first = stream.readline()
            if not first.strip():
                return
            dialect = self._dialect(first)
            header = next(csv.reader(io.StringIO(first), dialect), [])
            if not header:
                raise IngestionError("CSV file has no header row", path=source)
            header = [h.strip().lstrip("﻿") for h in header]

            reader = csv.reader(stream, dialect)
            for number, row in enumerate(reader, start=2):
                if not row or not any(cell.strip() for cell in row):
                    self.stats.skipped_empty += 1
                    continue
                record: dict[str, Any] = dict(zip(header, row, strict=False))
                if len(row) > len(header):
                    # Extra columns are kept rather than dropped: a shifted row
                    # is a data-quality signal the DLQ should be able to show.
                    record["_extra"] = row[len(header) :]
                self.stats.records_read += 1
                self.stats.bytes_read += sum(len(cell) for cell in row)
                yield RawRecord(
                    payload=record, source=source, line_number=number, context={"header": header}
                )


@source_registry.register("json_file")
class JsonArrayFileSource(LogSource):
    """Streams a JSON file that contains a top-level array of objects.

    A whole-file ``json.load`` would defeat the streaming design, so files
    above ``inline_limit`` are rejected with an actionable message pointing at
    JSONL — which is the format that actually scales.
    """

    name = "json_file"
    source_type = SourceType.FILE

    def __init__(
        self,
        path: str | Path,
        *,
        allowed_roots: Sequence[Path] | None = None,
        encoding: str = "utf-8",
        inline_limit: int = 256 * 1024 * 1024,
    ) -> None:
        super().__init__()
        self.path = (
            resolve_within(path, allowed_roots, must_exist=True)
            if allowed_roots
            else Path(path).expanduser().resolve()
        )
        self.encoding = encoding
        self.inline_limit = inline_limit

    def describe(self) -> str:
        return str(self.path)

    def read(self) -> Iterator[RawRecord]:
        size = self.path.stat().st_size
        if size > self.inline_limit:
            raise IngestionError(
                "JSON array file exceeds the in-memory limit; convert it to JSONL "
                "(one object per line) to stream it",
                size_bytes=size,
                limit=self.inline_limit,
            )
        try:
            text = self.path.read_text(encoding=self.encoding, errors="replace")
            decoded = json.loads(text)
        except (OSError, ValueError) as exc:
            raise IngestionError("failed to read the JSON file") from exc

        records = decoded if isinstance(decoded, list) else [decoded]
        source = str(self.path)
        for number, item in enumerate(records, start=1):
            if not isinstance(item, dict):
                self.stats.errors += 1
                continue
            self.stats.records_read += 1
            yield RawRecord(payload=item, source=source, line_number=number)


@source_registry.register("directory", "dir")
class DirectorySource(LogSource):
    """Fans out over every matching file beneath a directory.

    Files are read in sorted order so a run is deterministic and resumable:
    "processed up to ``access-2026-08-05.log``" is a meaningful checkpoint.
    """

    name = "directory"
    source_type = SourceType.DIRECTORY

    def __init__(
        self,
        path: str | Path,
        *,
        patterns: Sequence[str] = DEFAULT_PATTERNS,
        recursive: bool = True,
        allowed_roots: Sequence[Path] | None = None,
        follow_symlinks: bool = False,
        **file_kwargs: Any,
    ) -> None:
        super().__init__()
        self.root = (
            resolve_within(path, allowed_roots, must_exist=True)
            if allowed_roots
            else Path(path).expanduser().resolve()
        )
        if not self.root.is_dir():
            raise IngestionError("source is not a directory", path=str(self.root))
        self.patterns = tuple(patterns)
        self.recursive = recursive
        self.follow_symlinks = follow_symlinks
        self._file_kwargs = file_kwargs
        self._files = iter_files(
            self.root, self.patterns, recursive=recursive, follow_symlinks=follow_symlinks
        )

    def describe(self) -> str:
        return f"{self.root} ({len(self._files)} files)"

    @property
    def files(self) -> list[Path]:
        return list(self._files)

    def estimated_bytes(self) -> int | None:
        total = 0
        for path in self._files:
            try:
                total += path.stat().st_size
            except OSError:  # pragma: no cover
                continue
        return total

    def sample(self, count: int = 25) -> list[str]:
        return (
            open_file_source(self._files[0], **self._file_kwargs).sample(count)
            if self._files
            else []
        )

    def read(self) -> Iterator[RawRecord]:
        for path in self._files:
            source = open_file_source(path, **self._file_kwargs)
            try:
                with source:
                    yield from source.read()
            except IngestionError as exc:
                # One unreadable file must not abort a directory-wide job.
                self.stats.errors += 1
                log.warning(
                    "skipping unreadable file",
                    extra={"file": str(path), "error_type": type(exc).__name__},
                )
                continue
            finally:
                self.stats.records_read += source.stats.records_read
                self.stats.bytes_read += source.stats.bytes_read
                self.stats.skipped_empty += source.stats.skipped_empty


def open_file_source(path: str | Path, **kwargs: Any) -> LogSource:
    """Pick the right file source for a path based on its (real) extension."""
    resolved = Path(path)
    suffix = _effective_suffix(resolved)
    if suffix in TABULAR_EXTENSIONS:
        allowed = {"allowed_roots", "delimiter", "encoding", "encoding_errors", "max_bytes"}
        return CsvFileSource(resolved, **{k: v for k, v in kwargs.items() if k in allowed})
    if suffix == ".json":
        allowed = {"allowed_roots", "encoding", "inline_limit"}
        return JsonArrayFileSource(resolved, **{k: v for k, v in kwargs.items() if k in allowed})
    allowed = {
        "allowed_roots",
        "encoding",
        "encoding_errors",
        "max_line_bytes",
        "max_bytes",
        "skip_header",
    }
    return FileSource(resolved, **{k: v for k, v in kwargs.items() if k in allowed})


__all__ = [
    "DEFAULT_PATTERNS",
    "CsvFileSource",
    "DirectorySource",
    "FileSource",
    "JsonArrayFileSource",
    "open_file_source",
]
