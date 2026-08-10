"""Deduplication key strategies.

A strategy answers one question: *what makes two records "the same"?*  That is a
domain decision, not a technical one, so it is pluggable.

===================  ==========================================================
Strategy             When it is the right choice
===================  ==========================================================
``none``             Source is already exactly-once (a transactional DB read).
``event_id``         Re-ingesting the same file after a crash.  The id is
                     derived deterministically from content, so this is exact
                     and needs no configuration.
``content_hash``     Same line delivered twice by an at-least-once shipper
                     (Filebeat, Fluentd, Kafka).  Hashes the raw line.
``fields``           Logical duplicates that differ in irrelevant ways — two
                     replicas emitting the same event with different
                     ``request_id``.  Configure the fields that define identity.
===================  ==========================================================

Trade-offs
----------
* **Accuracy** — ``event_id`` and ``content_hash`` are exact (BLAKE2b-128; a
  collision needs ~2^64 records).  ``fields`` is deliberately *lossy*: it will
  collapse genuinely distinct records that happen to agree on the chosen
  fields.  Choose fields that include a timestamp.
* **Memory** — exact deduplication is O(distinct keys).  32 bytes per key means
  a million keys ≈ 60 MB with Python overhead.  The tracker is therefore
  bounded by an LRU: beyond the cap, duplicates separated by more than
  ``max_tracked_keys`` records are no longer detected.  That is a conscious
  choice — an unbounded set would OOM on a 10 M-record job.
* **Performance** — one hash and one dict probe per record, ~1.5 µs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import OrderedDict
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Final

from app.core.hashing import content_hash, fingerprint_fields
from app.core.registry import Registry
from app.models.log_event import LogEvent

dedup_registry: Registry[DeduplicationStrategy] = Registry("deduplication strategy")


class DeduplicationStrategy(ABC):
    """Maps an event to a key; equal keys mean duplicate records."""

    name: str = "base"

    @abstractmethod
    def key(self, event: LogEvent) -> str | None:
        """Return the identity key, or ``None`` to exempt this record."""

    def describe(self) -> str:
        return self.name


@dedup_registry.register("none", "off", "disabled")
class NoDeduplication(DeduplicationStrategy):
    """Passes everything through — the source guarantees uniqueness."""

    name = "none"

    def key(self, event: LogEvent) -> str | None:  # noqa: ARG002 - interface method
        return None


@dedup_registry.register("event_id", "id")
class EventIdStrategy(DeduplicationStrategy):
    """Uses the deterministic ``event_id``.  Exact and configuration-free."""

    name = "event_id"

    def key(self, event: LogEvent) -> str | None:
        return event.event_id or None


@dedup_registry.register("content_hash", "content", "raw")
class ContentHashStrategy(DeduplicationStrategy):
    """Hashes the raw line (falling back to the message)."""

    name = "content_hash"

    def key(self, event: LogEvent) -> str | None:
        payload = event.raw_message or event.message
        return content_hash(payload) if payload else None


@dedup_registry.register("fields", "configurable")
class FieldsStrategy(DeduplicationStrategy):
    """Fingerprints an operator-chosen tuple of fields."""

    name = "fields"

    def __init__(self, fields: Sequence[str] = ("timestamp", "service", "level", "message")):
        if not fields:
            raise ValueError("at least one field is required for field-based deduplication")
        self.fields = tuple(fields)

    def key(self, event: LogEvent) -> str | None:
        row = {name: getattr(event, name, None) for name in self.fields}
        if all(value is None for value in row.values()):
            return None
        return fingerprint_fields(row, self.fields)

    def describe(self) -> str:
        return f"fields({', '.join(self.fields)})"


# --------------------------------------------------------------------------- #
# Membership tracking
# --------------------------------------------------------------------------- #
class SeenKeys:
    """Bounded LRU set of keys already observed.

    ``OrderedDict`` gives O(1) insert, lookup and eviction of the oldest key,
    which is what keeps memory flat regardless of dataset size.
    """

    __slots__ = ("_keys", "evictions", "max_size")

    def __init__(self, max_size: int = 1_000_000) -> None:
        if max_size < 1:
            raise ValueError("max_size must be >= 1")
        self.max_size = max_size
        self._keys: OrderedDict[str, None] = OrderedDict()
        self.evictions = 0

    def add(self, key: str) -> bool:
        """Record ``key``; return ``True`` if it had not been seen."""
        if key in self._keys:
            self._keys.move_to_end(key)
            return False
        self._keys[key] = None
        if len(self._keys) > self.max_size:
            self._keys.popitem(last=False)
            self.evictions += 1
        return True

    def __contains__(self, key: object) -> bool:
        return key in self._keys

    def __len__(self) -> int:
        return len(self._keys)

    def clear(self) -> None:
        self._keys.clear()
        self.evictions = 0


@dataclass(slots=True)
class DedupStats:
    seen: int = 0
    unique: int = 0
    duplicates: int = 0
    exempt: int = 0
    evictions: int = 0

    @property
    def duplicate_rate(self) -> float:
        return self.duplicates / self.seen if self.seen else 0.0

    def as_dict(self) -> dict[str, float | int]:
        return {
            "seen": self.seen,
            "unique": self.unique,
            "duplicates": self.duplicates,
            "exempt": self.exempt,
            "evictions": self.evictions,
            "duplicate_rate": round(self.duplicate_rate, 6),
        }


class Deduplicator:
    """Applies a strategy plus bounded membership tracking to a stream."""

    def __init__(
        self,
        strategy: DeduplicationStrategy | None = None,
        *,
        max_tracked_keys: int = 1_000_000,
    ) -> None:
        self.strategy = strategy or ContentHashStrategy()
        self.seen = SeenKeys(max_tracked_keys)
        self.stats = DedupStats()

    @classmethod
    def from_settings(cls, settings: object) -> Deduplicator:
        """Build from :class:`app.core.config.DeduplicationSettings`."""
        strategy_name = getattr(settings, "strategy", "content_hash")
        if strategy_name == "fields":
            strategy: DeduplicationStrategy = FieldsStrategy(getattr(settings, "fields", ()))
        else:
            strategy = dedup_registry.create(strategy_name)
        return cls(strategy, max_tracked_keys=getattr(settings, "max_tracked_keys", 1_000_000))

    def is_duplicate(self, event: LogEvent) -> bool:
        """``True`` when this record has already been seen in this run."""
        self.stats.seen += 1
        key = self.strategy.key(event)
        if key is None:
            self.stats.exempt += 1
            self.stats.unique += 1
            return False
        if self.seen.add(key):
            self.stats.unique += 1
            return False
        self.stats.duplicates += 1
        return True

    def filter(self, events: Iterable[LogEvent]) -> Iterator[LogEvent]:
        """Yield only first occurrences — lazily, never materialising input."""
        for event in events:
            if not self.is_duplicate(event):
                yield event

    def partition(self, events: Iterable[LogEvent]) -> Iterator[tuple[LogEvent, bool]]:
        """Yield ``(event, is_duplicate)`` so the caller can dead-letter dupes."""
        for event in events:
            yield event, self.is_duplicate(event)

    def snapshot(self) -> dict[str, float | int | str]:
        self.stats.evictions = self.seen.evictions
        return {"strategy": self.strategy.describe(), **self.stats.as_dict()}

    def reset(self) -> None:
        self.seen.clear()
        self.stats = DedupStats()


#: Approximate memory cost per tracked key, measured on CPython 3.12 — used by
#: the CLI to warn before a configuration that will not fit in RAM.
BYTES_PER_TRACKED_KEY: Final[int] = 120


def estimate_memory_mb(max_tracked_keys: int) -> float:
    return max_tracked_keys * BYTES_PER_TRACKED_KEY / 1024**2


__all__ = [
    "BYTES_PER_TRACKED_KEY",
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
