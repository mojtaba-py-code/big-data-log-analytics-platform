"""Parsers for unstructured and semi-structured plain-text logs.

Covers the long tail: Python ``logging`` output, Java/Log4j, syslog, Nginx
*error* logs (as opposed to access logs), and the generic
``<timestamp> <LEVEL> <message>`` shape almost every application emits.

Performance
-----------
Each pattern is compiled once at class definition and tried in order of
specificity.  The timestamp prefix is extracted with a single alternation, so a
typical line costs two regex matches, not one per candidate format.

Security
--------
Every quantifier is bounded (``{0,4096}`` etc.) and no pattern nests an
unbounded repetition inside another — the two ingredients of catastrophic
backtracking.  A hostile 1 MB line therefore costs linear time, and the
ingestion layer caps line length before the parser is even reached.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final

from app.core.exceptions import ParseError
from app.core.timeutil import parse_timestamp
from app.models.enums import LogLevel
from app.models.log_event import LogEvent
from app.parsers.base import LogParser, ParseContext, coerce_duration_ms, parser_registry

#: Timestamp shapes seen at the start of a line, most specific first.
_TIMESTAMP_PATTERNS: Final[tuple[str, ...]] = (
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?",
    r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}",
    r"\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}",
    r"[A-Za-z]{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2}",
    r"\d{10,13}(?:\.\d{1,6})?",
)

_LEADING_TIMESTAMP: Final[re.Pattern[str]] = re.compile(
    r"^\[?(" + "|".join(_TIMESTAMP_PATTERNS) + r")\]?[\s:|-]{0,3}"
)

_LEVEL_TOKEN: Final[re.Pattern[str]] = re.compile(
    r"\b(TRACE|DEBUG|INFO(?:RMATION)?|NOTICE|WARN(?:ING)?|ERROR|ERR|CRIT(?:ICAL)?|"
    r"FATAL|ALERT|EMERG(?:ENCY)?|PANIC|SEVERE)\b",
    re.IGNORECASE,
)

#: ``[module]``/``(logger)``/``logger.name -`` immediately after the level.
_LOGGER_TOKEN: Final[re.Pattern[str]] = re.compile(
    r"^[\s:|-]{0,3}(?:\[([^\]\s]{1,120})\]|\(([^)\s]{1,120})\)|"
    r"([A-Za-z_][A-Za-z0-9_.]{2,119})\s+[-:]\s)"
)

#: Structured key hints commonly appended to text lines.
_INLINE_KV: Final[re.Pattern[str]] = re.compile(
    r"\b(request_id|trace_id|correlation_id|user_id|status|duration|latency|ip)"
    r"[=:]\s*([^\s,;]{1,256})",
    re.IGNORECASE,
)


@parser_registry.register("plaintext", "text", "generic")
class PlainTextParser(LogParser):
    """Generic ``<timestamp> <LEVEL> [logger] <message>`` parser.

    This is the platform's catch-all.  Its :attr:`confidence` is deliberately
    the lowest so the detector only picks it when no specific parser matches;
    it accepts essentially anything, which would otherwise shadow the others.
    """

    name = "plaintext"
    confidence = 10
    extensions = (".log", ".txt", ".out")

    def can_parse(self, sample: Sequence[str]) -> bool:
        return any(line.strip() for line in sample)

    def parse(self, raw: str, context: ParseContext) -> LogEvent:
        line = raw.rstrip("\r\n")
        if not line.strip():
            raise ParseError("empty line")

        remainder = line
        timestamp = None
        match = _LEADING_TIMESTAMP.match(line)
        if match:
            timestamp = parse_timestamp(match.group(1), default_year=context.default_year)
            remainder = line[match.end() :]

        level = LogLevel.UNKNOWN
        level_match = _LEVEL_TOKEN.search(remainder[:120])
        if level_match:
            level = LogLevel.coerce(level_match.group(1))
            start, stop = level_match.start(), level_match.end()
            # A bracketed level ("[ERROR]") must have its brackets removed too,
            # but "[" may never be stripped generally — that would destroy the
            # "[logger.name]" token the next step looks for.
            before, after = remainder[start - 1 : start], remainder[stop : stop + 1]
            if before in "[(" and after in "])" and start > 0:
                start -= 1
                stop += 1
            remainder = (remainder[:start] + remainder[stop:]).lstrip(" :|-")

        logger_name = None
        logger_match = _LOGGER_TOKEN.match(remainder)
        if logger_match:
            logger_name = next(g for g in logger_match.groups() if g)
            remainder = remainder[logger_match.end() :]

        message = remainder.strip(" \t:-|")
        fields: dict[str, object] = {
            "timestamp": timestamp,
            "level": level,
            "message": message,
            "logger": logger_name,
        }
        self._absorb_inline_pairs(message, fields)
        return self._finalize(fields, raw, context)

    @staticmethod
    def _absorb_inline_pairs(message: str, fields: dict[str, object]) -> None:
        """Promote well-known ``key=value`` hints embedded in the message."""
        for key, value in _INLINE_KV.findall(message[:2_048]):
            canonical = key.lower()
            if canonical in {"trace_id", "correlation_id"}:
                canonical = "request_id"
            if canonical in {"duration", "latency"}:
                parsed = coerce_duration_ms(value)
                if parsed is not None:
                    fields.setdefault("response_time_ms", parsed)
            elif canonical == "status":
                if value.isdigit() and 100 <= int(value) <= 599:
                    fields.setdefault("status_code", int(value))
            elif canonical == "ip":
                fields.setdefault("ip_address", value)
            else:
                fields.setdefault(canonical, value)


@parser_registry.register("syslog", "rfc3164", "rfc5424")
class SyslogParser(LogParser):
    """RFC 3164 (BSD) and RFC 5424 syslog lines.

    ``<priority>`` encodes facility and severity in one integer:
    ``severity = pri % 8``.  Decoding it is what lets syslog records join the
    same severity ladder as application logs.
    """

    name = "syslog"
    confidence = 75
    extensions = (".log",)

    _RFC5424 = re.compile(
        r"^<(?P<pri>\d{1,3})>(?P<version>\d)\s"
        r"(?P<ts>\S{1,64})\s(?P<host>\S{1,255})\s(?P<app>\S{1,64})\s"
        r"(?P<procid>\S{1,64})\s(?P<msgid>\S{1,64})\s"
        r"(?P<sd>-|\[[^\]]{0,2048}\])\s?(?P<msg>.{0,65536})$"
    )
    _RFC3164 = re.compile(
        r"^(?:<(?P<pri>\d{1,3})>)?"
        r"(?P<ts>[A-Za-z]{3}\s{1,2}\d{1,2} \d{2}:\d{2}:\d{2})\s"
        r"(?P<host>\S{1,255})\s"
        r"(?P<tag>[\w./\-]{1,64})(?:\[(?P<pid>\d{1,10})\])?:\s?"
        r"(?P<msg>.{0,65536})$"
    )

    _SEVERITY_TO_LEVEL = {
        0: LogLevel.EMERGENCY,
        1: LogLevel.ALERT,
        2: LogLevel.CRITICAL,
        3: LogLevel.ERROR,
        4: LogLevel.WARNING,
        5: LogLevel.NOTICE,
        6: LogLevel.INFO,
        7: LogLevel.DEBUG,
    }

    def can_parse(self, sample: Sequence[str]) -> bool:
        lines = [line for line in sample if line.strip()][:20]
        if not lines:
            return False
        hits = sum(1 for line in lines if self._RFC5424.match(line) or self._RFC3164.match(line))
        return hits >= max(1, len(lines) // 2)

    def parse(self, raw: str, context: ParseContext) -> LogEvent:
        line = raw.rstrip("\r\n")
        match = self._RFC5424.match(line) or self._RFC3164.match(line)
        if not match:
            raise ParseError("not a syslog line")
        groups = match.groupdict()

        level = LogLevel.UNKNOWN
        if groups.get("pri"):
            severity = int(groups["pri"]) % 8
            level = self._SEVERITY_TO_LEVEL.get(severity, LogLevel.UNKNOWN)
        message = groups.get("msg") or ""
        if level is LogLevel.UNKNOWN:
            token = _LEVEL_TOKEN.search(message[:120])
            if token:
                level = LogLevel.coerce(token.group(1))

        fields: dict[str, object] = {
            "timestamp": parse_timestamp(groups.get("ts"), default_year=context.default_year),
            "level": level,
            "message": message.strip(),
            "hostname": groups.get("host"),
            "service": groups.get("app") or groups.get("tag"),
        }
        metadata = {
            k: groups[k] for k in ("procid", "pid", "msgid", "sd", "version") if groups.get(k)
        }
        if metadata:
            fields["metadata"] = metadata
        return self._finalize(fields, raw, context)


@parser_registry.register("nginx_error", "nginx-error")
class NginxErrorLogParser(LogParser):
    """Nginx ``error.log`` lines.

    Format: ``2026/08/07 14:32:10 [error] 1234#0: *567 message, client: 1.2.3.4,
    server: api, request: "GET /x HTTP/1.1", upstream: "...", host: "..."``.
    The trailing ``key: value`` tail carries the request context that makes
    these lines joinable with access logs.
    """

    name = "nginx_error"
    confidence = 85
    extensions = (".log",)

    _PATTERN = re.compile(
        r"^(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) "
        r"\[(?P<level>[a-z]{4,10})\] "
        r"(?P<pid>\d{1,10})#(?P<tid>\d{1,10}):"
        r"(?: \*(?P<cid>\d{1,15}))? (?P<msg>.{0,65536})$"
    )
    _TAIL = re.compile(r'(client|server|request|host|upstream|referrer): "?([^",]{0,2048})"?')

    def can_parse(self, sample: Sequence[str]) -> bool:
        lines = [line for line in sample if line.strip()][:20]
        return bool(lines) and sum(1 for line in lines if self._PATTERN.match(line)) >= max(
            1, len(lines) // 2
        )

    def parse(self, raw: str, context: ParseContext) -> LogEvent:
        match = self._PATTERN.match(raw.rstrip("\r\n"))
        if not match:
            raise ParseError("not an nginx error line")
        groups = match.groupdict()
        message = groups["msg"]

        fields: dict[str, object] = {
            "timestamp": parse_timestamp(groups["ts"]),
            "level": LogLevel.coerce(groups["level"]),
            "message": message.strip(),
            "logger": "nginx",
        }
        metadata: dict[str, str] = {"pid": groups["pid"]}
        for key, value in self._TAIL.findall(message):
            if key == "client":
                fields["ip_address"] = value
            elif key == "server":
                fields["hostname"] = value
            elif key == "request":
                parts = value.split(" ", 2)
                if len(parts) >= 2:
                    fields["http_method"] = parts[0]
                    fields["endpoint"] = parts[1].split("?", 1)[0]
            elif key == "referrer":
                fields["referrer"] = value
            else:
                metadata[key] = value
        fields["metadata"] = metadata
        return self._finalize(fields, raw, context)


__all__ = ["NginxErrorLogParser", "PlainTextParser", "SyslogParser"]
