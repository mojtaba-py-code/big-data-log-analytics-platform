"""Storage interface and the Arrow schema.

Responsibility
--------------
Define *what* a storage backend must do, so business logic never depends on
Parquet, DuckDB or any particular file layout.  Swapping Parquet for Delta,
Iceberg or S3 means writing one class, not touching the pipeline.

The explicit Arrow schema
-------------------------
Letting Arrow infer types per batch is the classic way to end up with an
unreadable dataset: one batch where every ``status_code`` is null infers
``null`` type, the next infers ``int64``, and the two files can no longer be
scanned together.  Declaring the schema once fixes types for every writer.

Type choices
------------
* ``timestamp[us, UTC]`` — microsecond precision is what logs actually carry,
  and an explicit timezone stops readers from guessing.
* ``dictionary<string>`` for ``level``/``service``/``environment`` — these have
  very low cardinality; dictionary encoding cuts file size by ~70 % and makes
  group-by aggregations dramatically faster.
* ``int16`` for ``status_code``, ``int64`` for ``bytes_sent`` — no reason to
  spend 8 bytes on a value bounded by 599.
* ``metadata`` as a JSON string rather than a struct — see
  :meth:`app.models.log_event.LogEvent.to_row`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator, Sequence
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from app.core.registry import Registry
from app.models.log_event import LogEvent


def log_event_arrow_schema() -> Any:
    """The canonical Arrow schema for the processed layer."""
    import pyarrow as pa

    dict_string = pa.dictionary(pa.int32(), pa.string())
    return pa.schema(
        [
            pa.field("event_id", pa.string(), nullable=False),
            pa.field("timestamp", pa.timestamp("us", tz="UTC"), nullable=False),
            pa.field("ingested_at", pa.timestamp("us", tz="UTC"), nullable=False),
            pa.field("source", pa.string()),
            pa.field("source_type", dict_string),
            pa.field("service", dict_string),
            pa.field("hostname", dict_string),
            pa.field("environment", dict_string),
            pa.field("level", dict_string),
            pa.field("logger", dict_string),
            pa.field("message", pa.string()),
            pa.field("ip_address", pa.string()),
            pa.field("user_id", pa.string()),
            pa.field("request_id", pa.string()),
            pa.field("http_method", dict_string),
            pa.field("endpoint", pa.string()),
            pa.field("status_code", pa.int16()),
            pa.field("response_time_ms", pa.float64()),
            pa.field("bytes_sent", pa.int64()),
            pa.field("user_agent", pa.string()),
            pa.field("referrer", pa.string()),
            pa.field("metadata", pa.string()),
            pa.field("raw_message", pa.string()),
            pa.field("parser", dict_string),
        ]
    )


class StorageBackend(ABC):
    """Write and read normalised records, one physical format per subclass."""

    name: str = "base"
    extension: str = "dat"

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.files_written: list[Path] = []
        self.records_written = 0

    # -- writing ------------------------------------------------------------ #
    @abstractmethod
    def write(self, events: Iterable[LogEvent], *, run_id: str = "adhoc") -> list[Path]:
        """Persist ``events``; return the files touched."""

    @abstractmethod
    def flush(self) -> None:
        """Force buffered data to disk."""

    def close(self) -> None:
        self.flush()

    # -- reading ------------------------------------------------------------ #
    @abstractmethod
    def read(
        self, start: datetime | None = None, end: datetime | None = None, limit: int | None = None
    ) -> Iterator[dict[str, Any]]:
        """Stream stored rows back, pruned by time range where possible."""

    def paths(self, start: datetime | None = None, end: datetime | None = None) -> list[Path]:
        """Files covering a time range."""
        from app.storage.partitioning import prune_partitions

        return [
            file
            for partition in prune_partitions(self.root, start, end)
            for file in sorted(partition.glob(f"*.{self.extension}"))
        ]

    def stats(self) -> dict[str, Any]:
        files = list(self.root.rglob(f"*.{self.extension}"))
        return {
            "backend": self.name,
            "root": str(self.root),
            "files": len(files),
            "bytes": sum(f.stat().st_size for f in files if f.exists()),
            "records_written": self.records_written,
        }

    # -- context manager ---------------------------------------------------- #
    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def batched(events: Iterable[LogEvent], size: int) -> Iterator[list[LogEvent]]:
    """Chunk a stream into lists of at most ``size`` — never materialises all."""
    batch: list[LogEvent] = []
    for event in events:
        batch.append(event)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def rows_to_columns(rows: Sequence[dict[str, Any]], columns: Sequence[str]) -> dict[str, list[Any]]:
    """Transpose row dicts into column lists for Arrow."""
    return {column: [row.get(column) for row in rows] for column in columns}


#: Registry of storage backends.
storage_registry: Registry[StorageBackend] = Registry("storage backend")


__all__ = [
    "StorageBackend",
    "batched",
    "log_event_arrow_schema",
    "rows_to_columns",
    "storage_registry",
]
