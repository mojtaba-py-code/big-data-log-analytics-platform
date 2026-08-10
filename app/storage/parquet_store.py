"""Parquet storage backend — the platform's primary processed layer.

Why Parquet
-----------
* **Columnar**: an analytics query touching 3 of 24 columns reads ~1/8 of the
  bytes a row format would.
* **Compressed**: zstd on log data typically gives 8-15x over raw text, and
  dictionary-encoded low-cardinality columns compress far better than that.
* **Statistics per row-group**: min/max on ``timestamp`` lets DuckDB skip whole
  row-groups inside a file, on top of directory-level partition pruning.
* **Self-describing**: the schema travels with the data, so a file written
  today is readable by any engine years later.

Memory behaviour
----------------
Records are buffered per partition up to ``batch_size`` rows, converted to an
Arrow table and appended as one row-group.  Peak memory is therefore
``partitions × batch_size × row_size``, not dataset size.  With the default
50 000-row batches and daily partitions, a 10 M-record ingest holds well under
200 MB regardless of total volume.

Crash safety
------------
Each writer writes to ``.part-<n>.parquet.tmp`` and renames on close.  A crash
leaves a ``.tmp`` file that no reader picks up (readers glob ``*.parquet``),
so a partially written file can never corrupt a query result.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from app.core.exceptions import StorageError
from app.core.logging import get_logger
from app.core.paths import ensure_directory, safe_filename
from app.models.log_event import LOG_EVENT_COLUMNS, LogEvent
from app.storage.base import (
    StorageBackend,
    batched,
    log_event_arrow_schema,
    rows_to_columns,
    storage_registry,
)
from app.storage.partitioning import group_by_partition, prune_partitions

log = get_logger(__name__)

_COMPRESSION_ALIASES = {"none": None, "zstd": "zstd", "snappy": "snappy", "gzip": "gzip"}


@storage_registry.register("parquet")
class ParquetStore(StorageBackend):
    """Partitioned Parquet writer/reader."""

    name = "parquet"
    extension = "parquet"

    def __init__(
        self,
        root: Path,
        *,
        batch_size: int = 50_000,
        compression: str = "zstd",
        partition_keys: tuple[str, ...] = ("year", "month", "day"),
        row_group_size: int | None = None,
    ) -> None:
        super().__init__(root)
        self.batch_size = max(1_000, batch_size)
        self.compression = _COMPRESSION_ALIASES.get(compression, "zstd")
        self.partition_keys = partition_keys
        self.row_group_size = row_group_size or self.batch_size
        self._schema = log_event_arrow_schema()
        self._writers: dict[Path, Any] = {}
        self._temp_paths: dict[Path, Path] = {}
        self._sequence = 0

    # -- writing ------------------------------------------------------------ #
    def write(self, events: Iterable[LogEvent], *, run_id: str = "adhoc") -> list[Path]:
        """Stream events into partitioned Parquet files."""
        written: list[Path] = []
        safe_run = safe_filename(run_id, fallback="adhoc", max_length=48)
        for batch in batched(events, self.batch_size):
            for key, bucket in group_by_partition(batch, self.partition_keys).items():
                directory = self.root.joinpath(
                    *(
                        f"{name}={value}"
                        for name, value in zip(self.partition_keys, key, strict=True)
                    )
                )
                path = self._append(directory, bucket, safe_run)  # type: ignore[arg-type]
                if path not in written:
                    written.append(path)
            self.records_written += len(batch)
        self.files_written.extend(p for p in written if p not in self.files_written)
        return written

    def _append(self, directory: Path, events: list[LogEvent], run_id: str) -> Path:
        import pyarrow as pa
        import pyarrow.parquet as pq

        final_path = directory / f"part-{run_id}.{self.extension}"
        writer = self._writers.get(final_path)
        if writer is None:
            ensure_directory(directory)
            temp_path = directory / f".part-{run_id}.{self.extension}.tmp"
            try:
                writer = pq.ParquetWriter(
                    temp_path,
                    self._schema,
                    compression=self.compression,
                    use_dictionary=True,
                    write_statistics=True,
                )
            except Exception as exc:  # noqa: BLE001 - pyarrow raises many types
                raise StorageError("failed to open a Parquet writer", path=str(temp_path)) from exc
            self._writers[final_path] = writer
            self._temp_paths[final_path] = temp_path

        rows = [event.to_row() for event in events]
        columns = rows_to_columns(rows, LOG_EVENT_COLUMNS)
        try:
            table = pa.Table.from_pydict(columns, schema=self._schema)
            writer.write_table(table, row_group_size=self.row_group_size)
        except (pa.ArrowInvalid, pa.ArrowTypeError, ValueError) as exc:
            raise StorageError(
                "record batch does not conform to the storage schema",
                path=str(final_path),
                detail=str(exc)[:200],
            ) from exc
        return final_path

    def flush(self) -> None:
        """Close writers and atomically publish their files."""
        errors: list[str] = []
        for final_path, writer in list(self._writers.items()):
            temp_path = self._temp_paths.get(final_path)
            try:
                writer.close()
                if temp_path and temp_path.exists():
                    # os.replace is atomic on both POSIX and Windows.
                    if final_path.exists():
                        final_path.unlink()
                    temp_path.replace(final_path)  # atomic on POSIX and Windows
            except OSError as exc:
                errors.append(f"{final_path.name}: {exc.strerror}")
            finally:
                self._writers.pop(final_path, None)
                self._temp_paths.pop(final_path, None)
        if errors:
            raise StorageError("failed to finalise Parquet files", failures=errors)

    # -- reading ------------------------------------------------------------ #
    def read(
        self, start: datetime | None = None, end: datetime | None = None, limit: int | None = None
    ) -> Iterator[dict[str, Any]]:
        """Stream rows back, one row-group at a time.

        Reading batch-wise (rather than ``read_table``) keeps memory flat when
        exporting a large slice.
        """
        import pyarrow.parquet as pq

        yielded = 0
        for path in self.paths(start, end):
            try:
                parquet_file = pq.ParquetFile(path)
            except Exception:  # noqa: BLE001 - skip a corrupt file, keep going
                log.warning("skipping unreadable parquet file", extra={"file": str(path)})
                continue
            for batch in parquet_file.iter_batches(batch_size=10_000):
                for row in batch.to_pylist():
                    if start and row["timestamp"] and row["timestamp"] < start:
                        continue
                    if end and row["timestamp"] and row["timestamp"] > end:
                        continue
                    yield row
                    yielded += 1
                    if limit is not None and yielded >= limit:
                        return

    def dataset_files(
        self, start: datetime | None = None, end: datetime | None = None
    ) -> list[str]:
        """Glob patterns for DuckDB, restricted to pruned partitions."""
        partitions = prune_partitions(self.root, start, end)
        return [str(partition / f"*.{self.extension}") for partition in partitions]

    def row_count(self, start: datetime | None = None, end: datetime | None = None) -> int:
        """Row count read from Parquet footers — no data pages are touched."""
        import pyarrow.parquet as pq

        total = 0
        for path in self.paths(start, end):
            try:
                total += pq.ParquetFile(path).metadata.num_rows
            except Exception:  # noqa: BLE001 - a corrupt footer must not abort a count
                log.warning("could not read parquet footer", extra={"file": str(path)})
                continue
        return total


__all__ = ["ParquetStore"]
