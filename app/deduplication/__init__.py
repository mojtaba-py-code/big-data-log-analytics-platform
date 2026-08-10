"""Deduplication layer."""

from __future__ import annotations

from app.deduplication.strategies import (
    ContentHashStrategy,
    DeduplicationStrategy,
    Deduplicator,
    DedupStats,
    EventIdStrategy,
    FieldsStrategy,
    NoDeduplication,
    SeenKeys,
    dedup_registry,
    estimate_memory_mb,
)

__all__ = [
    "ContentHashStrategy",
    "DedupStats",
    "DeduplicationStrategy",
    "Deduplicator",
    "EventIdStrategy",
    "FieldsStrategy",
    "NoDeduplication",
    "SeenKeys",
    "dedup_registry",
    "estimate_memory_mb",
]
