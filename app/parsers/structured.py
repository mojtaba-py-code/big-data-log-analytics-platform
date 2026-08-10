"""Parsers for already-structured input: JSON lines, CSV rows, database rows.

These share one code path — :meth:`StructuredParser.parse_record` — because the
hard part is not decoding the container but *mapping heterogeneous field names
onto the canonical schema*.  That mapping lives once, in
:func:`app.parsers.base.map_structured_record`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

from app.core.exceptions import ParseError
from app.models.log_event import LogEvent
from app.parsers.base import (
    LogParser,
    ParseContext,
    map_structured_record,
    normalise_key,
    parser_registry,
)

#: Depth limit for flattening nested objects.  Deeply nested structures are
#: flattened into ``metadata`` with dotted keys rather than recursed forever —
#: an attacker-supplied 10 000-level document must not blow the stack.
MAX_FLATTEN_DEPTH = 4


def flatten(record: Mapping[str, Any], *, prefix: str = "", depth: int = 0) -> dict[str, Any]:
    """Flatten nested objects into dotted keys (``http.method`` → ``http_method``).

    Real-world structured logs nest heavily (ECS, OpenTelemetry, Docker).  The
    alias table works on flat keys, so flattening is what lets ``{"http":
    {"status_code": 500}}`` map onto ``status_code`` without a bespoke rule.
    """
    out: dict[str, Any] = {}
    for key, value in record.items():
        name = f"{prefix}{key}"
        if isinstance(value, Mapping) and depth < MAX_FLATTEN_DEPTH:
            nested = flatten(value, prefix=f"{name}_", depth=depth + 1)
            # A nested key wins only if the flat name is not already taken.
            for nested_key, nested_value in nested.items():
                out.setdefault(nested_key, nested_value)
            # Keep the leaf name too: {"http": {"method": ...}} should match
            # the ``method`` alias, not only ``http_method``.
            for nested_key, nested_value in nested.items():
                leaf = nested_key[len(name) + 1 :]
                if leaf and leaf not in out:
                    out[leaf] = nested_value
        else:
            out[name] = value
    return out


class StructuredParser(LogParser):
    """Base for parsers whose input is a mapping."""

    #: Optional ``source key -> canonical field`` overrides from configuration.
    field_map: ClassVar[dict[str, str]] = {}

    def __init__(self, field_map: Mapping[str, str] | None = None) -> None:
        self._field_map = {normalise_key(k): v for k, v in (field_map or self.field_map).items()}

    def parse_record(
        self,
        record: Mapping[str, Any],
        context: ParseContext,
        *,
        raw_text: str | None = None,
    ) -> LogEvent:
        """Map a mapping onto :class:`LogEvent`.

        ``raw_text`` lets a caller that already has the verbatim source line
        hand it over; re-serialising the decoded object costs ~20 µs a record
        and loses the original byte-for-byte form.
        """
        if not record:
            raise ParseError("empty record")
        flat = flatten(record)
        fields = map_structured_record(flat, extra_aliases=self._field_map)
        if not fields.get("message"):
            # No obvious message field: keep the record readable rather than
            # storing an empty string.
            fields["message"] = _fallback_message(flat)
        if not context.keep_raw:
            raw = ""
        elif raw_text is not None:
            raw = raw_text
        else:
            raw = json.dumps(record, default=str, ensure_ascii=False)
        return self._finalize(fields, raw, context)

    def parse(self, raw: str, context: ParseContext) -> LogEvent:  # pragma: no cover - overridden
        raise NotImplementedError


def _fallback_message(flat: Mapping[str, Any]) -> str:
    """Build a readable message from a record that has no message field."""
    parts = [
        f"{k}={v}"
        for k, v in list(flat.items())[:12]
        if v is not None and not isinstance(v, (dict, list))
    ]
    return " ".join(parts)[:4_096]


@parser_registry.register("json", "jsonl", "ndjson")
class JsonLineParser(StructuredParser):
    """One JSON object per line (JSONL / NDJSON), or a JSON array element."""

    name = "json"
    confidence = 90
    extensions = (".json", ".jsonl", ".ndjson")

    def can_parse(self, sample: Sequence[str]) -> bool:
        candidates = [line.strip() for line in sample if line.strip()]
        if not candidates:
            return False
        hits = 0
        for line in candidates[:20]:
            if not (line.startswith("{") and line.endswith("}")):
                continue
            try:
                hits += isinstance(json.loads(line), dict)
            except (ValueError, RecursionError):
                continue
        return hits >= max(1, len(candidates[:20]) // 2)

    def parse(self, raw: str, context: ParseContext) -> LogEvent:
        text = raw.strip().rstrip(",")
        if not text:
            raise ParseError("empty line")
        try:
            decoded = json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise ParseError(f"invalid JSON: {exc.__class__.__name__}") from exc
        if not isinstance(decoded, dict):
            raise ParseError("JSON record is not an object")
        return self.parse_record(decoded, context, raw_text=raw)


@parser_registry.register("csv", "tsv")
class CsvRowParser(StructuredParser):
    """A CSV/TSV row that has already been paired with its header.

    Row splitting belongs to the *source* (which owns the header and the
    dialect); this parser only performs the mapping, so a malformed CSV file
    fails once at the source rather than once per row.
    """

    name = "csv"
    confidence = 60
    extensions = (".csv", ".tsv")

    def can_parse(self, sample: Sequence[str]) -> bool:
        rows = [line for line in sample if line.strip()]
        if len(rows) < 2:
            return False
        for delimiter in (",", "\t", ";"):
            counts = [row.count(delimiter) for row in rows[:10]]
            if counts[0] >= 2 and len(set(counts)) == 1:
                return True
        return False

    def parse(self, raw: str, context: ParseContext) -> LogEvent:
        """Parse a pre-joined ``key=value`` row (fallback path)."""
        import csv as _csv
        import io

        header = context.extra.get("header")
        if not header:
            raise ParseError("CSV parsing requires a header in the parse context")
        try:
            row = next(_csv.reader(io.StringIO(raw), dialect=context.extra.get("dialect", "excel")))
        except (StopIteration, _csv.Error) as exc:
            raise ParseError(f"malformed CSV row: {exc}") from exc
        record = dict(zip(header, row, strict=False))
        return self.parse_record(record, context)


@parser_registry.register("keyvalue", "logfmt", "kv")
class KeyValueParser(StructuredParser):
    """``logfmt``-style lines: ``ts=... level=info msg="hello world"``."""

    name = "keyvalue"
    confidence = 70

    _TOKEN = re.compile(
        r'([A-Za-z_][A-Za-z0-9_.\-]{0,63})=(?:"([^"]{0,4096})"|\'([^\']{0,4096})\'|([^\s]{0,4096}))'
    )

    def can_parse(self, sample: Sequence[str]) -> bool:
        lines = [line for line in sample if line.strip()][:20]
        if not lines:
            return False
        scored = sum(1 for line in lines if len(self._TOKEN.findall(line)) >= 3)
        return scored >= max(1, len(lines) // 2)

    def parse(self, raw: str, context: ParseContext) -> LogEvent:
        matches = self._TOKEN.findall(raw)
        if len(matches) < 2:
            raise ParseError("not a key=value line")
        record = {
            key: next((v for v in (quoted, single, bare) if v), "")
            for key, quoted, single, bare in matches
        }
        return self.parse_record(record, context)


__all__ = ["CsvRowParser", "JsonLineParser", "KeyValueParser", "StructuredParser", "flatten"]
