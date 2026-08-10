"""JSONL and CSV storage backends.

Parquet is the default for the processed layer, but text formats earn their
place:

* **JSONL** for the *raw* layer and for interchange.  Append-only, readable
  with ``tail``, survives partial writes (a truncated last line is the only
  damage), and needs no schema — which matters for raw data that has not been
  normalised yet.
* **CSV** for export to spreadsheets and legacy tooling.  Lossy by nature
  (everything becomes text, embedded newlines need quoting), so it is offered
  for export rather than as a processing format.

Both stream: rows are written as they arrive and never accumulate in memory.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

from app.core.exceptions import StorageError
from app.core.logging import get_logger
from app.core.paths import ensure_directory, safe_filename
from app.core.timeutil import to_iso
from app.models.log_event import LOG_EVENT_COLUMNS, LogEvent
from app.storage.base import StorageBackend, storage_registry
from app.storage.partitioning import partition_path

log = get_logger(__name__)


class _PartitionedTextStore(StorageBackend):
    """Shared plumbing: one append-mode handle per partition."""

    def __init__(
        self,
        root: Path,
        *,
        partition_keys: tuple[str, ...] = ("year", "month", "day"),
        flush_every: int = 1_000,
    ) -> None:
        super().__init__(root)
        self.partition_keys = partition_keys
        self.flush_every = flush_every
        self._handles: dict[Path, TextIO] = {}
        self._temp: dict[Path, Path] = {}
        self._since_flush = 0

    def _handle_for(self, moment: datetime, run_id: str) -> tuple[Path, TextIO]:
        directory = partition_path(self.root, moment, self.partition_keys)
        final_path = directory / f"part-{run_id}.{self.extension}"
        handle = self._handles.get(final_path)
        if handle is None:
            ensure_directory(directory)
            temp_path = directory / f".part-{run_id}.{self.extension}.tmp"
            try:
                handle = temp_path.open("w", encoding="utf-8", newline="")
            except OSError as exc:
                raise StorageError("failed to open an output file", path=str(temp_path)) from exc
            self._handles[final_path] = handle
            self._temp[final_path] = temp_path
            self._on_open(handle)
        return final_path, handle

    def _on_open(self, handle: TextIO) -> None:
        """Hook for writing a header."""

    def flush(self) -> None:
        errors: list[str] = []
        for final_path, handle in list(self._handles.items()):
            temp_path = self._temp.get(final_path)
            try:
                handle.flush()
                handle.close()
                if temp_path and temp_path.exists():
                    if final_path.exists():
                        final_path.unlink()
                    temp_path.replace(final_path)  # atomic on POSIX and Windows
            except OSError as exc:
                errors.append(f"{final_path.name}: {exc.strerror}")
            finally:
                self._handles.pop(final_path, None)
                self._temp.pop(final_path, None)
        self._since_flush = 0
        if errors:
            raise StorageError("failed to finalise output files", failures=errors)


@storage_registry.register("jsonl", "json")
class JsonlStore(_PartitionedTextStore):
    """One JSON object per line, partitioned by event date."""

    name = "jsonl"
    extension = "jsonl"

    def write(self, events: Iterable[LogEvent], *, run_id: str = "adhoc") -> list[Path]:
        safe_run = safe_filename(run_id, fallback="adhoc", max_length=48)
        touched: list[Path] = []
        for event in events:
            path, handle = self._handle_for(event.timestamp, safe_run)
            handle.write(json.dumps(event.to_api_dict(), ensure_ascii=False, default=str) + "\n")
            self.records_written += 1
            self._since_flush += 1
            if self._since_flush >= self.flush_every:
                handle.flush()
                self._since_flush = 0
            if path not in touched:
                touched.append(path)
        self.files_written.extend(p for p in touched if p not in self.files_written)
        return touched

    def read(
        self, start: datetime | None = None, end: datetime | None = None, limit: int | None = None
    ) -> Iterator[dict[str, Any]]:
        yielded = 0
        for path in self.paths(start, end):
            with path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        log.warning("skipping corrupt JSONL row", extra={"file": str(path)})
                        continue
                    stamp = row.get("timestamp")
                    if start and stamp and stamp < to_iso(start):
                        continue
                    if end and stamp and stamp > to_iso(end):
                        continue
                    yield row
                    yielded += 1
                    if limit is not None and yielded >= limit:
                        return


@storage_registry.register("csv")
class CsvStore(_PartitionedTextStore):
    """RFC 4180 CSV export.

    ``csv.writer`` handles quoting, which is what stops a message containing a
    comma or a newline from silently shifting every downstream column — the
    reason hand-rolled CSV writers corrupt data.
    """

    name = "csv"
    extension = "csv"

    def __init__(self, root: Path, **kwargs: Any) -> None:
        super().__init__(root, **kwargs)
        self._writers: dict[Path, Any] = {}

    def _on_open(self, handle: TextIO) -> None:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(LOG_EVENT_COLUMNS)
        self._writers[Path(handle.name)] = writer

    def write(self, events: Iterable[LogEvent], *, run_id: str = "adhoc") -> list[Path]:
        safe_run = safe_filename(run_id, fallback="adhoc", max_length=48)
        touched: list[Path] = []
        for event in events:
            path, handle = self._handle_for(event.timestamp, safe_run)
            writer = self._writers[Path(handle.name)]
            row = event.to_row()
            writer.writerow(
                [
                    to_iso(row[column]) if isinstance(row[column], datetime) else row[column]
                    for column in LOG_EVENT_COLUMNS
                ]
            )
            self.records_written += 1
            if path not in touched:
                touched.append(path)
        self.files_written.extend(p for p in touched if p not in self.files_written)
        return touched

    def read(
        self, start: datetime | None = None, end: datetime | None = None, limit: int | None = None
    ) -> Iterator[dict[str, Any]]:
        yielded = 0
        for path in self.paths(start, end):
            with path.open("r", encoding="utf-8", newline="") as stream:
                for row in csv.DictReader(stream):
                    stamp = row.get("timestamp")
                    if start and stamp and stamp < to_iso(start):
                        continue
                    if end and stamp and stamp > to_iso(end):
                        continue
                    yield dict(row)
                    yielded += 1
                    if limit is not None and yielded >= limit:
                        return

    def flush(self) -> None:
        super().flush()
        self._writers.clear()


__all__ = ["CsvStore", "JsonlStore"]
