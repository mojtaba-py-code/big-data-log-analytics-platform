"""Record validation.

Responsibility
--------------
Decide whether a parsed :class:`~app.models.log_event.LogEvent` is fit to enter
the processed dataset.  Validation *never* mutates a record — repairs belong to
:mod:`app.transformation.cleaning`, which runs first.  Keeping the two apart is
what makes both testable: a cleaner is a pure function, a validator is a pure
predicate.

Two severities
--------------
``ERROR``   the record is rejected and dead-lettered.
``WARNING`` the record is kept but the issue is counted, so an operator can see
            that (say) 12 % of records arrive without a service name without
            losing that data.

Performance
-----------
Rules are plain callables held in a tuple and executed in order of cost:
cheap attribute checks first, regex/parse-based checks last.  The whole set
costs ~2 µs per record.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import Final

from app.core.config import ValidationSettings
from app.core.timeutil import MAX_TIMESTAMP, MIN_TIMESTAMP, utcnow
from app.models.enums import LogLevel, RejectReason
from app.models.log_event import LogEvent


class IssueSeverity(StrEnum):
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """One rule violation."""

    rule: str
    reason: RejectReason
    severity: IssueSeverity = IssueSeverity.ERROR
    detail: str = ""

    @property
    def is_fatal(self) -> bool:
        return self.severity is IssueSeverity.ERROR


@dataclass(frozen=True, slots=True)
class ValidationResult:
    """Outcome for a single record."""

    valid: bool
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def fatal_issue(self) -> ValidationIssue | None:
        return next((i for i in self.issues if i.is_fatal), None)

    @property
    def warnings(self) -> tuple[ValidationIssue, ...]:
        return tuple(i for i in self.issues if not i.is_fatal)


Rule = Callable[[LogEvent], ValidationIssue | None]

VALID_OK: Final[ValidationResult] = ValidationResult(valid=True)


class RecordValidator:
    """Runs a configured rule set over every record."""

    def __init__(
        self,
        settings: ValidationSettings | None = None,
        *,
        extra_rules: Sequence[Rule] = (),
    ) -> None:
        self.settings = settings or ValidationSettings()
        self._allowed_levels = {LogLevel.coerce(lvl) for lvl in self.settings.allowed_levels}
        self._rules: tuple[Rule, ...] = (*self._build_rules(), *extra_rules)

    # -- rule construction -------------------------------------------------- #
    def _build_rules(self) -> tuple[Rule, ...]:
        cfg = self.settings
        max_future = timedelta(seconds=cfg.max_future_skew_seconds)
        max_age = timedelta(days=cfg.max_age_days)

        def timestamp_present(event: LogEvent) -> ValidationIssue | None:
            if event.timestamp is None:
                return ValidationIssue(
                    "timestamp_present", RejectReason.MISSING_TIMESTAMP, detail="no timestamp"
                )
            return None

        def timestamp_range(event: LogEvent) -> ValidationIssue | None:
            ts = event.timestamp
            if ts is None:
                return None
            if not (MIN_TIMESTAMP <= ts <= MAX_TIMESTAMP):
                return ValidationIssue(
                    "timestamp_range",
                    RejectReason.TIMESTAMP_OUT_OF_RANGE,
                    detail="timestamp outside supported epoch",
                )
            now = utcnow()
            if ts > now + max_future:
                # Future-dated records corrupt every time-window aggregation
                # they land in, so they are rejected rather than clamped.
                return ValidationIssue(
                    "timestamp_future",
                    RejectReason.TIMESTAMP_OUT_OF_RANGE,
                    detail=f"timestamp is {(ts - now).total_seconds():.0f}s in the future",
                )
            if ts < now - max_age:
                return ValidationIssue(
                    "timestamp_stale",
                    RejectReason.TIMESTAMP_OUT_OF_RANGE,
                    severity=IssueSeverity.WARNING,
                    detail="record is older than the retention window",
                )
            return None

        def message_present(event: LogEvent) -> ValidationIssue | None:
            if event.message.strip():
                return None
            severity = IssueSeverity.ERROR if cfg.require_message else IssueSeverity.WARNING
            return ValidationIssue(
                "message_present",
                RejectReason.MISSING_MESSAGE,
                severity=severity,
                detail="empty message",
            )

        def message_length(event: LogEvent) -> ValidationIssue | None:
            if len(event.message) > cfg.max_message_length:
                return ValidationIssue(
                    "message_length",
                    RejectReason.MESSAGE_TOO_LONG,
                    detail=f"message is {len(event.message)} chars",
                )
            return None

        def level_allowed(event: LogEvent) -> ValidationIssue | None:
            if event.level not in self._allowed_levels:
                return ValidationIssue(
                    "level_allowed",
                    RejectReason.INVALID_LEVEL,
                    severity=IssueSeverity.WARNING,
                    detail=f"level {event.level} is not in the allow-list",
                )
            return None

        def status_code_valid(event: LogEvent) -> ValidationIssue | None:
            if event.status_code is not None and not (100 <= event.status_code <= 599):
                return ValidationIssue(
                    "status_code_valid",
                    RejectReason.INVALID_STATUS_CODE,
                    detail=f"status {event.status_code} outside 100-599",
                )
            return None

        def ip_valid(event: LogEvent) -> ValidationIssue | None:
            if event.ip_address is None:
                return None
            try:
                ipaddress.ip_address(event.ip_address)
            except ValueError:
                return ValidationIssue(
                    "ip_valid",
                    RejectReason.INVALID_IP,
                    severity=IssueSeverity.WARNING,
                    detail="unparseable IP address",
                )
            return None

        def response_time_valid(event: LogEvent) -> ValidationIssue | None:
            rt = event.response_time_ms
            if rt is None:
                return None
            if rt < 0 or rt > 86_400_000:
                return ValidationIssue(
                    "response_time_valid",
                    RejectReason.INVALID_RESPONSE_TIME,
                    detail=f"response time {rt} ms is implausible",
                )
            return None

        def schema_consistency(event: LogEvent) -> ValidationIssue | None:
            """Cross-field sanity: an HTTP record needs a method or a status."""
            if event.endpoint and event.status_code is None and event.http_method is None:
                return ValidationIssue(
                    "schema_consistency",
                    RejectReason.SCHEMA_VIOLATION,
                    severity=IssueSeverity.WARNING,
                    detail="endpoint present without method or status",
                )
            return None

        rules: list[Rule] = []
        if cfg.require_timestamp:
            rules.append(timestamp_present)
        rules += [
            timestamp_range,
            message_present,
            message_length,
            level_allowed,
            status_code_valid,
            response_time_valid,
            ip_valid,
            schema_consistency,
        ]
        return tuple(rules)

    # -- execution ---------------------------------------------------------- #
    def validate(self, event: LogEvent) -> ValidationResult:
        """Run every rule; stop collecting once a fatal issue is found."""
        issues: list[ValidationIssue] = []
        for rule in self._rules:
            issue = rule(event)
            if issue is None:
                continue
            issues.append(issue)
            if issue.is_fatal:
                # Short-circuit: the record is going to the DLQ regardless, and
                # the first fatal reason is the actionable one.
                return ValidationResult(valid=False, issues=tuple(issues))
        return ValidationResult(valid=True, issues=tuple(issues)) if issues else VALID_OK

    def validate_many(
        self, events: Iterable[LogEvent]
    ) -> Iterable[tuple[LogEvent, ValidationResult]]:
        """Lazily validate a stream — never materialises the input."""
        for event in events:
            yield event, self.validate(event)


__all__ = [
    "IssueSeverity",
    "RecordValidator",
    "Rule",
    "ValidationIssue",
    "ValidationResult",
]
