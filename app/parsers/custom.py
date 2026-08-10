"""Configurable parsers for bespoke log formats.

Rather than hard-coding every format a customer might have, an operator
declares one in configuration:

.. code-block:: yaml

    parsers:
      - name: payments-audit
        pattern: '^(?P<timestamp>\\S+) \\| (?P<level>\\w+) \\| (?P<message>.*)$'
        field_map: {txn: request_id}
        timestamp_format: "%Y-%m-%dT%H:%M:%S"

Security
--------
A regular expression supplied through configuration is *code*.  Two controls
apply:

1. :func:`assert_safe_pattern` rejects constructs known to cause catastrophic
   backtracking (nested unbounded quantifiers, unbounded alternation inside a
   repeat) and caps overall pattern length.
2. Matching runs against a length-capped line, so even a missed pathological
   pattern is bounded by ``processing.max_line_bytes``.

This is defence in depth, not a proof: config files are trusted input written
by administrators, and the checks exist to catch mistakes rather than a
determined insider.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from app.core.exceptions import ConfigurationError, ParseError
from app.core.timeutil import ensure_utc, parse_timestamp
from app.models.enums import LogLevel
from app.models.log_event import LogEvent
from app.parsers.base import (
    LogParser,
    ParseContext,
    coerce_duration_ms,
    coerce_int,
    normalise_key,
    parser_registry,
)

MAX_PATTERN_LENGTH: Final[int] = 4_096

#: Nested quantifier: a group that repeats and whose body also repeats, e.g.
#: ``(a+)+``, ``(.*)*``, ``(\d+|\w+)*`` — the classic ReDoS shapes.
_NESTED_QUANTIFIER: Final[re.Pattern[str]] = re.compile(
    r"\((?:[^()]{0,200}?[+*]|[^()]{0,200}?\{\d+,\}\)?)[^()]{0,200}?\)\s*[+*]|"
    r"\([^()]{0,200}?\|[^()]{0,200}?\)\s*[+*]"
)


def assert_safe_pattern(pattern: str) -> None:
    """Reject regexes with obvious super-linear behaviour."""
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ConfigurationError(
            "custom parser pattern is too long", length=len(pattern), limit=MAX_PATTERN_LENGTH
        )
    if _NESTED_QUANTIFIER.search(pattern):
        raise ConfigurationError(
            "custom parser pattern contains a nested unbounded quantifier "
            "(potential catastrophic backtracking); rewrite it with bounded repeats",
        )
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ConfigurationError(f"invalid custom parser pattern: {exc}") from exc
    if not compiled.groupindex:
        raise ConfigurationError(
            "custom parser pattern must use named groups, e.g. (?P<message>...)"
        )


@dataclass(slots=True)
class CustomParserSpec:
    """Declarative definition of a bespoke format."""

    name: str
    pattern: str
    field_map: dict[str, str] = field(default_factory=dict)
    timestamp_format: str | None = None
    default_level: str = "UNKNOWN"
    #: Groups listed here go to ``metadata`` instead of being dropped.
    metadata_groups: tuple[str, ...] = ()
    multiline: bool = False

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> CustomParserSpec:
        try:
            return cls(
                name=str(data["name"]),
                pattern=str(data["pattern"]),
                field_map={str(k): str(v) for k, v in (data.get("field_map") or {}).items()},
                timestamp_format=data.get("timestamp_format"),
                default_level=str(data.get("default_level", "UNKNOWN")),
                metadata_groups=tuple(data.get("metadata_groups") or ()),
                multiline=bool(data.get("multiline", False)),
            )
        except KeyError as exc:
            raise ConfigurationError(f"custom parser is missing field {exc}") from exc


class RegexParser(LogParser):
    """Parser driven by a named-group regular expression.

    Group names are mapped onto canonical fields directly (``message``,
    ``level``, …) or through ``field_map`` for source-specific names.
    """

    confidence = 80
    #: Overrides the class-level name: each configured parser is distinct.
    name: str  # type: ignore[misc]

    def __init__(self, spec: CustomParserSpec) -> None:
        assert_safe_pattern(spec.pattern)
        flags = re.DOTALL if spec.multiline else 0
        self.spec = spec
        self.name = spec.name
        self._regex = re.compile(spec.pattern, flags)
        self._map = {normalise_key(k): v for k, v in spec.field_map.items()}
        self._default_level = LogLevel.coerce(spec.default_level)

    def can_parse(self, sample: Sequence[str]) -> bool:
        lines = [line for line in sample if line.strip()][:20]
        if not lines:
            return False
        hits = sum(1 for line in lines if self._regex.match(line))
        return hits >= max(1, (len(lines) * 2) // 3)

    def parse(self, raw: str, context: ParseContext) -> LogEvent:
        match = self._regex.match(raw.rstrip("\r\n"))
        if not match:
            raise ParseError(f"line does not match parser {self.name!r}")
        groups = {k: v for k, v in match.groupdict().items() if v is not None}
        fields: dict[str, Any] = {"level": self._default_level}
        metadata: dict[str, Any] = {}

        for group, value in groups.items():
            canonical = self._map.get(normalise_key(group), normalise_key(group))
            if group in self.spec.metadata_groups:
                metadata[canonical] = value
                continue
            self._assign(fields, canonical, value, metadata)

        if metadata:
            fields["metadata"] = metadata
        return self._finalize(fields, raw, context)

    def _assign(
        self, fields: dict[str, Any], canonical: str, value: str, metadata: dict[str, Any]
    ) -> None:
        match canonical:
            case "timestamp":
                fields["timestamp"] = self._parse_timestamp(value)
            case "level":
                fields["level"] = LogLevel.coerce(value)
            case "status_code":
                status = coerce_int(value)
                if status is not None and 100 <= status <= 599:
                    fields["status_code"] = status
            case "response_time_ms" | "response_time" | "duration":
                duration = coerce_duration_ms(value, canonical)
                if duration is not None:
                    fields["response_time_ms"] = duration
            case "bytes_sent" | "bytes":
                size = coerce_int(value)
                if size is not None and size >= 0:
                    fields["bytes_sent"] = size
            case (
                "message"
                | "service"
                | "hostname"
                | "logger"
                | "ip_address"
                | "user_id"
                | "request_id"
                | "endpoint"
                | "user_agent"
                | "referrer"
            ):
                fields[canonical] = value
            case "http_method":
                fields["http_method"] = value
            case _:
                metadata[canonical] = value

    def _parse_timestamp(self, value: str) -> datetime | None:
        if self.spec.timestamp_format:
            try:
                return ensure_utc(datetime.strptime(value, self.spec.timestamp_format))  # noqa: DTZ007
            except ValueError:
                # Fall through to the flexible parser: a single odd line should
                # not be dead-lettered because of a format edge case.
                pass
        return parse_timestamp(value)


#: Configured custom parsers, keyed by name.
#:
#: These are *instances*, not classes, because each carries its own compiled
#: pattern — which is why they live here instead of in ``parser_registry``
#: (a class registry).  :func:`app.parsers.get_parser` consults both.
custom_parsers: dict[str, RegexParser] = {}


def build_custom_parsers(
    specs: Sequence[Mapping[str, Any]], *, register: bool = True
) -> list[RegexParser]:
    """Instantiate (and optionally publish) parsers from configuration."""
    parsers: list[RegexParser] = []
    for raw_spec in specs:
        spec = CustomParserSpec.from_mapping(raw_spec)
        if spec.name in parser_registry:
            raise ConfigurationError(
                "custom parser name collides with a built-in parser", name=spec.name
            )
        parser = RegexParser(spec)
        parsers.append(parser)
        if register:
            custom_parsers[spec.name] = parser
    return parsers


def clear_custom_parsers() -> None:
    """Drop all configured custom parsers (used by tests and config reload)."""
    custom_parsers.clear()


__all__ = [
    "MAX_PATTERN_LENGTH",
    "CustomParserSpec",
    "RegexParser",
    "assert_safe_pattern",
    "build_custom_parsers",
    "clear_custom_parsers",
    "custom_parsers",
]
