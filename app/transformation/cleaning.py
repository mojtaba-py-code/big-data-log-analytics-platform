"""Data cleaning.

Responsibility
--------------
Repair recoverable defects *before* validation runs, so that records are not
dead-lettered for problems the platform can fix deterministically:

* control characters and ANSI escape sequences (log forging / terminal escapes)
* mojibake from a double-decoded UTF-8 payload
* inconsistent whitespace, tabs and non-breaking spaces
* empty-marker values (``-``, ``N/A``, ``null``, ``undefined``)
* oversized fields

Security
--------
Stripping control characters is not cosmetic.  A carriage return or line feed
inside a field lets an attacker inject a fake line into any downstream text
renderer (log forging), and ANSI escapes can rewrite an operator's terminal.
Both are removed here, once, for every source.

Cleaning is **lossless with respect to the original**: ``raw_message`` is left
untouched, so the unmodified line is always recoverable.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from typing import Final

from app.models.log_event import LogEvent

#: Values that mean "absent" in one log format or another.
EMPTY_MARKERS: Final[frozenset[str]] = frozenset(
    {"-", "--", "n/a", "na", "none", "null", "nil", "undefined", "unknown", "?", "(null)", ""}
)

_ANSI_ESCAPE: Final[re.Pattern[str]] = re.compile(r"\x1b\[[0-9;?]{0,32}[ -/]{0,8}[@-~]")
_CONTROL_CHARS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
#: Unicode space family: NBSP, the U+2000-200B run, ideographic space and the
#: BOM all appear in logs that passed through editors, browsers or consoles.
_WHITESPACE_RUN: Final[re.Pattern[str]] = re.compile("[ \t   -​  　﻿]+")
#: Line separators, including the Unicode ones most tooling forgets.
_NEWLINES: Final[re.Pattern[str]] = re.compile("[\r\n\v\f  ]+")


def clean_text(
    value: str | None,
    *,
    max_length: int | None = None,
    collapse_newlines: bool = True,
) -> str | None:
    """Normalise one text value; ``None`` for anything that means "absent".

    Runs once per field per record, so it is written as a series of guarded
    fast paths: ``str.isprintable`` and ``str.isascii`` are C-level scans and
    let a clean ASCII value skip every regex.  On real datasets that is the
    overwhelming majority of fields.
    """
    if value is None:
        return None
    text = value
    if not text.isprintable():
        # Covers ANSI escapes, NUL bytes, and every newline form at once.
        if "\x1b" in text:
            text = _ANSI_ESCAPE.sub("", text)
        if collapse_newlines:
            text = _NEWLINES.sub(" ", text)
        text = _CONTROL_CHARS.sub("", text)
    if not text.isascii():
        text = unicodedata.normalize("NFC", text)
        text = _WHITESPACE_RUN.sub(" ", text)
    elif "  " in text or "\t" in text:
        text = _WHITESPACE_RUN.sub(" ", text)
    text = text.strip()
    if text.lower() in EMPTY_MARKERS:
        return None
    if max_length is not None and len(text) > max_length:
        text = text[:max_length]
    return text


def fix_mojibake(text: str) -> str:
    """Undo one round of UTF-8-decoded-as-Latin-1 damage.

    Only applied when the text actually contains the tell-tale sequences,
    because the round-trip is lossy on genuinely Latin-1 content.
    """
    if not any(marker in text for marker in ("Ã", "â€", "Â", "�")):
        return text
    try:
        repaired = text.encode("latin-1", "strict").decode("utf-8", "strict")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return text
    return repaired


class RecordCleaner:
    """Applies the cleaning rules to a whole :class:`LogEvent`."""

    def __init__(
        self,
        *,
        max_message_length: int = 32_768,
        repair_encoding: bool = True,
        strip_query_strings: bool = True,
    ) -> None:
        self.max_message_length = max_message_length
        self.repair_encoding = repair_encoding
        self.strip_query_strings = strip_query_strings

    def clean(self, event: LogEvent) -> LogEvent:
        """Return a cleaned copy of ``event``.

        A copy rather than in-place mutation: pipeline stages must stay
        side-effect free so a failure mid-chain cannot leave a half-cleaned
        record in the caller's hands.
        """
        updates: dict[str, object] = {}

        message = clean_text(event.message, max_length=self.max_message_length)
        if self.repair_encoding and message:
            message = fix_mojibake(message)
        if message != event.message:
            updates["message"] = message or ""

        for field_name, limit in (
            ("service", 255),
            ("hostname", 255),
            ("logger", 255),
            ("user_id", 255),
            ("request_id", 255),
            ("user_agent", 1_024),
            ("referrer", 2_048),
        ):
            current = getattr(event, field_name)
            cleaned = clean_text(current, max_length=limit)
            if cleaned != current:
                updates[field_name] = cleaned

        endpoint = clean_text(event.endpoint, max_length=2_048)
        if endpoint and self.strip_query_strings:
            endpoint = endpoint.split("?", 1)[0].split("#", 1)[0] or "/"
        if endpoint != event.endpoint:
            updates["endpoint"] = endpoint

        if event.metadata:
            cleaned_meta = {
                key: clean_text(value, max_length=4_096) if isinstance(value, str) else value
                for key, value in event.metadata.items()
            }
            if cleaned_meta != event.metadata:
                updates["metadata"] = cleaned_meta

        if not updates:
            return event
        return event.model_copy(update=updates)

    def clean_many(self, events: Iterable[LogEvent]) -> Iterable[LogEvent]:
        for event in events:
            yield self.clean(event)


__all__ = ["EMPTY_MARKERS", "RecordCleaner", "clean_text", "fix_mojibake"]
