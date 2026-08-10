"""Storage layer: physical formats, partitioning, analytical engine, metadata."""

from __future__ import annotations

from pathlib import Path

from app.core.config import Settings
from app.storage.base import StorageBackend, log_event_arrow_schema, storage_registry
from app.storage.duckdb_engine import DuckDBEngine, validate_column
from app.storage.metadata import ApiKeyRecord, IngestCheckpoint, JobRun, MetadataStore
from app.storage.parquet_store import ParquetStore
from app.storage.partitioning import (
    glob_for_range,
    iter_partitions,
    partition_path,
    prune_partitions,
)
from app.storage.text_store import CsvStore, JsonlStore


def build_store(root: Path, settings: Settings, fmt: str | None = None) -> StorageBackend:
    """Instantiate the configured storage backend for a data layer."""
    chosen = fmt or settings.storage.format
    if chosen == "parquet":
        return ParquetStore(
            root,
            batch_size=settings.storage.write_batch_size,
            compression=settings.storage.compression,
            partition_keys=settings.storage.partition_by,
        )
    if chosen == "jsonl":
        return JsonlStore(root, partition_keys=settings.storage.partition_by)
    if chosen == "csv":
        return CsvStore(root, partition_keys=settings.storage.partition_by)
    return storage_registry.create(chosen, root)


def build_engine(settings: Settings, root: Path | None = None) -> DuckDBEngine:
    """Analytical engine over the processed layer."""
    return DuckDBEngine(
        root or settings.processed_path,
        memory_limit_mb=max(256, 128 * settings.processing.workers),
        threads=settings.processing.workers,
        temp_directory=settings.storage.data_root / ".duckdb-tmp",
    )


__all__ = [
    "ApiKeyRecord",
    "CsvStore",
    "DuckDBEngine",
    "IngestCheckpoint",
    "JobRun",
    "JsonlStore",
    "MetadataStore",
    "ParquetStore",
    "StorageBackend",
    "build_engine",
    "build_store",
    "glob_for_range",
    "iter_partitions",
    "log_event_arrow_schema",
    "partition_path",
    "prune_partitions",
    "storage_registry",
    "validate_column",
]
