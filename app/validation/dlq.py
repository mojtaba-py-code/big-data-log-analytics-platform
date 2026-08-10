"""Dead-letter queue.

Responsibility
--------------
Persist every record the pipeline could not accept, together with *why*, so
that no input is ever silently lost.  Three properties matter:

**Durability** — rejections are appended to disk, not held in memory, so a
crash mid-run does not lose the diagnostic trail.

**Replayability** — the original line is stored verbatim (masked), so once a
parser bug is fixed the rejected file can be re-ingested with
:func:`replay_rejected` rather than re-fetching the source.

**Boundedness** — a run that rejects ten million records must not fill the
disk.  ``max_records`` caps what is written while the *counters* stay exact,
so the summary is still truthful.

Format
------
JSONL, one rejection per line, partitioned by rejection date.  JSONL rather
than Parquet because rejections are written incrementally and read rarely; a
columnar format would buy nothing and complicate append-on-crash semantics.
"""

from __future__ import annotations

import json
import threading
from collections import Counter
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from app.core.logging import get_logger
from app.core.masking import Masker, default_masker
from app.core.paths import ensure_directory, safe_filename
from app.core.timeutil import partition_values
from app.models.enums import RejectReason
from app.models.log_event import LogEvent
from app.models.results import RejectedRecord

log = get_logger(__name__)

DEFAULT_MAX_RECORDS = 1_000_000
FLUSH_EVERY = 500


class DeadLetterQueue:
    """Append-only sink for rejected records.

    Thread-safe: the worker pool shares one queue per run so that rejection
    counts are global to the job rather than per-shard.
    """

    def __init__(
        self,
        root: Path,
        *,
        run_id: str = "adhoc",
        masker: Masker | None = None,
        max_records: int = DEFAULT_MAX_RECORDS,
        enabled: bool = True,
    ) -> None:
        self.root = root
        self.run_id = safe_filename(run_id, fallback="adhoc", max_length=64)
        self.max_records = max_records
        self.enabled = enabled
        self._masker = masker or default_masker
        self._counts: Counter[str] = Counter()
        self._written = 0
        self._dropped = 0
        self._handles: dict[Path, Any] = {}
        self._since_flush = 0
        self._lock = threading.Lock()

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

    # -- writing ------------------------------------------------------------ #
    def record(
        self,
        raw: str,
        reason: RejectReason,
        *,
        stage: str,
        detail: str = "",
        source: str = "unknown",
        line_number: int | None = None,
        partial: dict[str, Any] | None = None,
    ) -> RejectedRecord:
        """Register one rejection and persist it."""
        rejected = RejectedRecord(
            reason=reason,
            stage=stage,
            detail=self._masker.mask_text(detail)[:1_024],
            source=source,
            line_number=line_number,
            raw=self._masker.mask_text(raw)[:131_072],
            partial=self._masker.mask_mapping(partial or {}),
        )
        self._write(rejected)
        return rejected

    def record_event(
        self,
        event: LogEvent,
        reason: RejectReason,
        *,
        stage: str,
        detail: str = "",
    ) -> RejectedRecord:
        """Reject an already-parsed event (validation / dedup / storage)."""
        return self.record(
            event.raw_message or event.message,
            reason,
            stage=stage,
            detail=detail,
            source=event.source,
            partial={
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "service": event.service,
                "level": str(event.level),
            },
        )

    def _write(self, rejected: RejectedRecord) -> None:
        with self._lock:
            self._counts[str(rejected.reason)] += 1
            if not self.enabled:
                return
            if self._written >= self.max_records:
                self._dropped += 1
                if self._dropped == 1:
                    log.warning(
                        "dead-letter queue cap reached; further rejections are counted only",
                        extra={"max_records": self.max_records, "run_id": self.run_id},
                    )
                return
            handle = self._handle_for(rejected.rejected_at)
            handle.write(json.dumps(rejected.to_row(), default=str, ensure_ascii=False) + "\n")
            self._written += 1
            self._since_flush += 1
            if self._since_flush >= FLUSH_EVERY:
                handle.flush()
                self._since_flush = 0

    def _handle_for(self, moment: datetime) -> Any:
        parts = partition_values(moment)
        directory = (
            self.root / f"year={parts['year']}" / f"month={parts['month']}" / f"day={parts['day']}"
        )
        path = directory / f"rejected-{self.run_id}.jsonl"
        handle = self._handles.get(path)
        if handle is None:
            ensure_directory(directory)
            handle = path.open("a", encoding="utf-8", newline="")
            self._handles[path] = handle
        return handle

    # -- introspection ------------------------------------------------------ #
    @property
    def total(self) -> int:
        return sum(self._counts.values())

    @property
    def written(self) -> int:
        return self._written

    def counts(self) -> dict[str, int]:
        return dict(self._counts)

    def files(self) -> list[Path]:
        return sorted(self._handles)

    def summary(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "written": self._written,
            "dropped": self._dropped,
            "by_reason": dict(sorted(self._counts.items())),
            "files": [str(p) for p in self.files()],
        }

    def close(self) -> None:
        with self._lock:
            for handle in self._handles.values():
                try:
                    handle.flush()
                    handle.close()
                except OSError:  # pragma: no cover - best effort on shutdown
                    log.warning("failed to close a dead-letter file")
            self._handles.clear()


class NullDeadLetterQueue(DeadLetterQueue):
    """Counts rejections without touching the filesystem (tests, dry runs)."""

    def __init__(self) -> None:
        super().__init__(Path(), run_id="null", enabled=False)


def iter_rejected(root: Path, *, since: datetime | None = None) -> Iterator[dict[str, Any]]:
    """Stream previously rejected records from disk."""
    if not root.exists():
        return
    for path in sorted(root.rglob("rejected-*.jsonl")):
        with path.open("r", encoding="utf-8") as stream:
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    log.warning("skipping corrupt dead-letter line", extra={"file": str(path)})
                    continue
                if since is not None:
                    stamp = record.get("rejected_at")
                    if isinstance(stamp, str) and stamp < since.isoformat():
                        continue
                yield record


def replay_rejected(
    root: Path, *, reasons: set[RejectReason] | None = None
) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield ``(raw_line, metadata)`` for rejections eligible for a retry.

    Only *transient* categories are replayable by default.  Replaying a record
    that was rejected for being unparseable, without first changing a parser,
    would simply reject it again — so the caller must ask for those explicitly.
    """
    transient = {
        RejectReason.STORAGE_ERROR,
        RejectReason.TRANSFORM_ERROR,
        RejectReason.UNKNOWN,
    }
    wanted = {str(r) for r in (reasons or transient)}
    for record in iter_rejected(root):
        if record.get("reason") in wanted and record.get("raw"):
            yield record["raw"], record


def rejection_stats(root: Path) -> dict[str, int]:
    """Aggregate rejection counts per reason across all stored files."""
    counter: Counter[str] = Counter()
    for record in iter_rejected(root):
        counter[str(record.get("reason", "unknown"))] += 1
    return dict(sorted(counter.items()))


__all__ = [
    "DeadLetterQueue",
    "NullDeadLetterQueue",
    "iter_rejected",
    "rejection_stats",
    "replay_rejected",
]
