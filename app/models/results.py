"""Pipeline result objects: rejections and run statistics.

The platform never silently discards data.  Anything that cannot become a
:class:`~app.models.log_event.LogEvent` becomes a :class:`RejectedRecord`,
which is persisted alongside the good data with enough context to reproduce
the failure and, once fixed, to replay it.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field

from app.core.hashing import content_hash
from app.core.timeutil import to_iso, utcnow
from app.models.enums import RejectReason


class RejectedRecord(BaseModel):
    """A record that failed a pipeline stage — the dead-letter payload.

    ``raw`` is stored **masked**: a rejected record is still log data and may
    contain the very credential that made it malformed.
    """

    model_config = ConfigDict(extra="forbid")

    reason: RejectReason = RejectReason.UNKNOWN
    stage: str = "unknown"
    detail: str = Field(default="", max_length=1_024)
    source: str = "unknown"
    line_number: int | None = None
    raw: str = Field(default="", max_length=131_072)
    raw_hash: str = ""
    rejected_at: datetime = Field(default_factory=utcnow)
    partial: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, _context: Any) -> None:
        if not self.raw_hash and self.raw:
            object.__setattr__(self, "raw_hash", content_hash(self.raw))

    def to_row(self) -> dict[str, Any]:
        return {
            "rejected_at": self.rejected_at,
            "reason": str(self.reason),
            "stage": self.stage,
            "detail": self.detail,
            "source": self.source,
            "line_number": self.line_number,
            "raw": self.raw,
            "raw_hash": self.raw_hash,
            "partial": json.dumps(self.partial, default=str) if self.partial else None,
        }

    def to_api_dict(self) -> dict[str, Any]:
        row = self.to_row()
        row["rejected_at"] = to_iso(self.rejected_at)
        row["partial"] = self.partial
        return row


class StageStats(BaseModel):
    """Counters for a single pipeline stage."""

    model_config = ConfigDict(extra="forbid")

    name: str
    processed: int = 0
    passed: int = 0
    rejected: int = 0
    duration_seconds: float = 0.0

    @property
    def rejection_rate(self) -> float:
        return self.rejected / self.processed if self.processed else 0.0

    @property
    def throughput(self) -> float:
        return self.processed / self.duration_seconds if self.duration_seconds > 0 else 0.0


class PipelineResult(BaseModel):
    """Outcome of one end-to-end processing run.

    This object is what the CLI prints, the API returns and the metadata store
    persists.  It is intentionally serialisable and free of live handles.
    """

    model_config = ConfigDict(extra="forbid")

    run_id: str
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None

    sources: list[str] = Field(default_factory=list)
    bytes_read: int = 0
    lines_read: int = 0
    records_parsed: int = 0
    records_valid: int = 0
    records_rejected: int = 0
    records_duplicate: int = 0
    records_written: int = 0

    rejection_reasons: dict[str, int] = Field(default_factory=dict)
    stages: list[StageStats] = Field(default_factory=list)
    outputs: list[str] = Field(default_factory=list)
    peak_memory_mb: float = 0.0
    errors: list[str] = Field(default_factory=list)
    succeeded: bool = True

    # -- derived ------------------------------------------------------------ #
    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or utcnow()
        return max((end - self.started_at).total_seconds(), 0.0)

    @property
    def records_per_second(self) -> float:
        duration = self.duration_seconds
        return self.lines_read / duration if duration > 0 else 0.0

    @property
    def megabytes_per_second(self) -> float:
        duration = self.duration_seconds
        return (self.bytes_read / 1024**2) / duration if duration > 0 else 0.0

    @property
    def rejection_rate(self) -> float:
        total = self.records_parsed + self.records_rejected
        return self.records_rejected / total if total else 0.0

    def record_rejection(self, reason: RejectReason | str) -> None:
        key = str(reason)
        self.rejection_reasons[key] = self.rejection_reasons.get(key, 0) + 1
        self.records_rejected += 1

    def merge(self, other: PipelineResult) -> Self:
        """Fold a worker's partial result into this one."""
        self.bytes_read += other.bytes_read
        self.lines_read += other.lines_read
        self.records_parsed += other.records_parsed
        self.records_valid += other.records_valid
        self.records_rejected += other.records_rejected
        self.records_duplicate += other.records_duplicate
        self.records_written += other.records_written
        self.sources.extend(other.sources)
        self.outputs.extend(other.outputs)
        self.errors.extend(other.errors)
        self.stages.extend(other.stages)
        self.peak_memory_mb = max(self.peak_memory_mb, other.peak_memory_mb)
        self.succeeded = self.succeeded and other.succeeded
        for reason, count in other.rejection_reasons.items():
            self.rejection_reasons[reason] = self.rejection_reasons.get(reason, 0) + count
        return self

    def summary(self) -> dict[str, Any]:
        """Compact dict suitable for logging or a CLI table."""
        return {
            "run_id": self.run_id,
            "succeeded": self.succeeded,
            "duration_seconds": round(self.duration_seconds, 3),
            "lines_read": self.lines_read,
            "records_written": self.records_written,
            "records_rejected": self.records_rejected,
            "records_duplicate": self.records_duplicate,
            "rejection_rate": round(self.rejection_rate, 6),
            "records_per_second": round(self.records_per_second, 1),
            "megabytes_per_second": round(self.megabytes_per_second, 3),
            "peak_memory_mb": round(self.peak_memory_mb, 1),
            "rejection_reasons": dict(sorted(self.rejection_reasons.items())),
            "outputs": self.outputs,
        }


__all__ = ["PipelineResult", "RejectedRecord", "StageStats"]
