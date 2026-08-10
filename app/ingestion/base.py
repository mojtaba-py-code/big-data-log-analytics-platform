"""Ingestion interface.

Responsibility
--------------
A source knows how to *produce raw records* from somewhere — a file, a
directory, a database table, an HTTP endpoint, a Kafka topic — and nothing
else.  It does not parse, validate or store.

Contract
--------
``read()`` returns an **iterator**, never a list.  This is the single most
important design rule in the platform: a source that materialises its input
cannot process a 40 GB file on a 6 GB machine.  Every built-in source streams,
and any new source must too.

Sources also report ``bytes_read`` / ``records_read`` as they go, so the
pipeline can compute throughput without knowing what kind of source it has.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any, Self

from app.core.registry import Registry
from app.models.enums import SourceType


@dataclass(slots=True)
class RawRecord:
    """One unit of input, before parsing.

    ``payload`` is either a raw line (text sources) or an already-structured
    mapping (CSV rows, database rows, JSON API responses).  Carrying both in
    one type lets the pipeline treat every source identically.
    """

    payload: str | Mapping[str, Any]
    source: str = "unknown"
    line_number: int | None = None
    byte_size: int = 0
    context: dict[str, Any] = field(default_factory=dict)

    @property
    def is_structured(self) -> bool:
        return not isinstance(self.payload, str)

    @property
    def text(self) -> str:
        """Text form, for the dead-letter queue and content hashing."""
        if isinstance(self.payload, str):
            return self.payload
        import json

        return json.dumps(self.payload, default=str, ensure_ascii=False)


@dataclass(slots=True)
class SourceStats:
    records_read: int = 0
    bytes_read: int = 0
    skipped_empty: int = 0
    skipped_oversized: int = 0
    errors: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "records_read": self.records_read,
            "bytes_read": self.bytes_read,
            "skipped_empty": self.skipped_empty,
            "skipped_oversized": self.skipped_oversized,
            "errors": self.errors,
        }


class LogSource(ABC):
    """Base class for every ingestion source."""

    name: str = "base"
    source_type: SourceType = SourceType.UNKNOWN

    def __init__(self) -> None:
        self.stats = SourceStats()

    @abstractmethod
    def read(self) -> Iterator[RawRecord]:
        """Yield raw records lazily."""

    def describe(self) -> str:
        """Human-readable identifier used in logs and provenance fields."""
        return self.name

    # -- optional hints for the pipeline ---------------------------------- #
    def sample(self, count: int = 25) -> list[str]:  # noqa: ARG002 - interface method
        """Head of the stream, for format detection.  Empty if unsupported."""
        return []

    def suggested_service(self) -> str | None:
        """Service name implied by the source (e.g. the file's basename)."""
        return None

    def estimated_bytes(self) -> int | None:
        """Total size when known, for progress reporting."""
        return None

    def close(self) -> None:  # noqa: B027 - optional hook; most sources hold nothing
        """Release any resources.  Safe to call twice."""

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def __iter__(self) -> Iterator[RawRecord]:
        return self.read()


#: Registry of ingestion sources — the extension point for new inputs.
source_registry: Registry[LogSource] = Registry("source")


__all__ = ["LogSource", "RawRecord", "SourceStats", "source_registry"]
