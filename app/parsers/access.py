"""Apache / Nginx access-log parsers.

Two formats cover the overwhelming majority of web-server logs:

``common``    ``%h %l %u %t "%r" %>s %b``
``combined``  ``common`` plus ``"%{Referer}i" "%{User-Agent}i"``

Nginx's default ``combined`` is byte-identical to Apache's, and its widespread
``$request_time``/``$upstream_response_time`` extension simply appends numeric
fields — handled here as an optional tail rather than as a separate parser.

Security
--------
* The request line is attacker-controlled.  It is split on whitespace with a
  hard field cap; it is never interpreted, and the query string is stripped
  from ``endpoint`` so that per-endpoint aggregations do not become an index of
  every token an attacker probed (and do not leak tokens users sent in URLs).
* All quantifiers are bounded and non-nested, so a pathological request line
  cannot trigger catastrophic backtracking.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Sequence
from typing import Final
from urllib.parse import unquote

from app.core.exceptions import ParseError
from app.core.timeutil import parse_timestamp
from app.models.enums import LogLevel
from app.models.log_event import LogEvent
from app.parsers.base import LogParser, ParseContext, parser_registry

#: ``%h %l %u [%t] "%r" %>s %b`` with optional combined and timing tails.
_ACCESS_LOG: Final[re.Pattern[str]] = re.compile(
    r"^(?P<ip>[0-9a-fA-F:.]{3,45}|-)\s+"
    r"(?P<ident>\S{1,64})\s+"
    r"(?P<user>\S{1,255})\s+"
    r"\[(?P<time>[^\]]{1,64})\]\s+"
    r'"(?P<request>[^"]{0,8192})"\s+'
    r"(?P<status>\d{3}|-)\s+"
    r"(?P<bytes>\d{1,19}|-)"
    r'(?:\s+"(?P<referrer>[^"]{0,2048})"\s+"(?P<agent>[^"]{0,2048})")?'
    r"(?P<tail>.{0,512})$"
)

#: Trailing numeric fields Nginx appends: request_time, upstream_response_time.
_TIMING_TAIL: Final[re.Pattern[str]] = re.compile(r"(\d{1,6}\.\d{1,6}|\d{1,9})")

#: ``X-Forwarded-For``-style proxy chains appended by some configurations.
_FORWARDED: Final[re.Pattern[str]] = re.compile(r'"((?:[0-9a-fA-F:.]{3,45}(?:,\s*)?){1,10})"')

#: Status classes that make an access-log line an "error" in level terms.
_LEVEL_FOR_STATUS: Final[dict[int, LogLevel]] = {
    2: LogLevel.INFO,
    3: LogLevel.INFO,
    4: LogLevel.WARNING,
    5: LogLevel.ERROR,
}


@parser_registry.register("access", "apache", "nginx", "combined", "common")
class AccessLogParser(LogParser):
    """Apache/Nginx common **and** combined access-log formats."""

    name = "access"
    confidence = 95
    extensions = (".log", ".txt")

    def can_parse(self, sample: Sequence[str]) -> bool:
        lines = [line for line in sample if line.strip()][:20]
        if not lines:
            return False
        hits = sum(1 for line in lines if _ACCESS_LOG.match(line))
        return hits >= max(1, (len(lines) * 2) // 3)

    def parse(self, raw: str, context: ParseContext) -> LogEvent:
        match = _ACCESS_LOG.match(raw.rstrip("\r\n"))
        if not match:
            raise ParseError("not an access-log line")
        groups = match.groupdict()

        method, endpoint, protocol = _split_request(groups["request"])
        status = int(groups["status"]) if groups["status"].isdigit() else None
        level = (
            _LEVEL_FOR_STATUS.get(status // 100, LogLevel.INFO)
            if status is not None
            else LogLevel.INFO
        )

        fields: dict[str, object] = {
            "timestamp": parse_timestamp(groups["time"]),
            "level": level,
            "ip_address": groups["ip"],
            "http_method": method,
            "endpoint": endpoint,
            "status_code": status,
            "bytes_sent": int(groups["bytes"]) if groups["bytes"].isdigit() else None,
            "referrer": _clean_optional(groups.get("referrer")),
            "user_agent": _clean_optional(groups.get("agent")),
            "message": f"{method or '-'} {endpoint or '-'} {status or '-'}",
        }

        user = groups.get("user")
        if user and user != "-":
            fields["user_id"] = user

        metadata: dict[str, object] = {}
        if protocol:
            metadata["protocol"] = protocol
        if groups.get("ident") and groups["ident"] != "-":
            metadata["ident"] = groups["ident"]

        tail = (groups.get("tail") or "").strip()
        if tail:
            self._absorb_tail(tail, fields, metadata)
        if metadata:
            fields["metadata"] = metadata
        return self._finalize(fields, raw, context)

    @staticmethod
    def _absorb_tail(tail: str, fields: dict[str, object], metadata: dict[str, object]) -> None:
        """Interpret Nginx's optional trailing fields.

        Convention: the first numeric value is ``$request_time`` (seconds), the
        second is ``$upstream_response_time``.  Quoted values are treated as a
        forwarded-for chain.
        """
        forwarded = _FORWARDED.search(tail)
        if forwarded:
            chain = forwarded.group(1)
            metadata["forwarded_for"] = chain
            fields.setdefault("ip_address", chain.split(",")[0].strip())
        numbers = _TIMING_TAIL.findall(tail)
        if numbers:
            with contextlib.suppress(ValueError):  # the regex guarantees numeric
                fields["response_time_ms"] = float(numbers[0]) * 1000.0
        if len(numbers) > 1:
            with contextlib.suppress(ValueError):  # pragma: no cover
                metadata["upstream_time_ms"] = float(numbers[1]) * 1000.0


def _split_request(request: str) -> tuple[str | None, str | None, str | None]:
    """Split ``"GET /path?x=1 HTTP/1.1"`` into its three parts.

    The path is percent-decoded (once — never repeatedly, which would let
    ``%252e%252e`` decode into ``..``) and the query string is dropped.
    """
    parts = request.split(" ", 2)
    if len(parts) == 1:
        return None, None, None
    method = parts[0][:16].upper() or None
    target = parts[1] if len(parts) > 1 else ""
    protocol = parts[2][:16] if len(parts) > 2 else None
    path = target.split("?", 1)[0].split("#", 1)[0]
    with contextlib.suppress(UnicodeDecodeError, ValueError):  # pragma: no cover
        path = unquote(path, errors="replace")
    # Strip control characters an attacker may embed to forge log lines.
    path = "".join(ch for ch in path if ch.isprintable())[:2_048]
    return method, path or "/", protocol


def _clean_optional(value: str | None) -> str | None:
    if not value or value == "-":
        return None
    return value


__all__ = ["AccessLogParser"]
