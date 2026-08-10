"""Validation layer: predicates over records, plus the dead-letter queue."""

from __future__ import annotations

from app.validation.dlq import (
    DeadLetterQueue,
    NullDeadLetterQueue,
    iter_rejected,
    rejection_stats,
    replay_rejected,
)
from app.validation.validators import (
    IssueSeverity,
    RecordValidator,
    ValidationIssue,
    ValidationResult,
)

__all__ = [
    "DeadLetterQueue",
    "IssueSeverity",
    "NullDeadLetterQueue",
    "RecordValidator",
    "ValidationIssue",
    "ValidationResult",
    "iter_rejected",
    "rejection_stats",
    "replay_rejected",
]
