"""Automatic log-format detection.

Responsibility
--------------
Given the first N lines of a source, decide which parser to use.  Getting this
right means an operator can run ``loganalytics ingest server.log`` without
knowing or declaring the format — while still being able to override it with
``--format`` when the guess is wrong.

Algorithm
---------
1. **Extension hint** — a ``.jsonl`` file is almost certainly JSON.  Worth a
   bonus, never a decision on its own (plenty of JSON lives in ``.log``).
2. **Structural vote** — every parser's ``can_parse`` runs over the sample.
3. **Trial parse** — candidates are scored by how many sample lines they parse
   *successfully*, which eliminates parsers that match structurally but produce
   junk.
4. **Confidence tie-break** — a specific parser beats the catch-all.

The sample is bounded (default 25 lines), so detection is O(parsers × sample)
and independent of file size.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from app.core.exceptions import ParseError
from app.core.logging import get_logger
from app.parsers.base import LogParser, ParseContext, parser_registry
from app.parsers.custom import custom_parsers

log = get_logger(__name__)

#: Bonus applied when the file extension matches a parser's declared type.
_EXTENSION_BONUS = 15
#: Weight of a successful trial parse, per line.
_PARSE_WEIGHT = 4


@dataclass(frozen=True, slots=True)
class DetectionResult:
    parser_name: str
    score: float
    parsed_lines: int
    sample_size: int
    candidates: tuple[tuple[str, float], ...]

    @property
    def success_rate(self) -> float:
        return self.parsed_lines / self.sample_size if self.sample_size else 0.0


def available_parsers() -> dict[str, LogParser]:
    """Every parser instance available for detection (built-in + configured)."""
    instances: dict[str, LogParser] = {}
    for name in parser_registry.names():
        try:
            instances[name] = parser_registry.create(name)
        except TypeError:  # pragma: no cover - parser needing constructor args
            log.debug("parser %s cannot be auto-instantiated", name)
    instances.update(custom_parsers)
    return instances


def detect_format(
    sample: Sequence[str],
    *,
    filename: str | Path | None = None,
    context: ParseContext | None = None,
) -> DetectionResult:
    """Pick the best parser for ``sample``.

    Always returns a result: the catch-all plain-text parser is the floor, so
    detection never fails outright — an unparseable file produces a low success
    rate that the caller can surface instead of an exception.
    """
    lines = [line for line in sample if line.strip()][:100]
    extension = Path(filename).suffix.lower() if filename else ""
    scores: dict[str, float] = {}
    parsed_counts: dict[str, int] = {}
    ctx = context or ParseContext(source=str(filename or "sample"))

    for name, parser in available_parsers().items():
        score = 0.0
        try:
            structural = parser.can_parse(lines)
        except Exception:  # noqa: BLE001 - can_parse must never break detection
            log.debug("parser %s raised during can_parse", name)
            continue
        if structural:
            score += parser.confidence
        if extension and extension in parser.extensions:
            score += _EXTENSION_BONUS

        parsed = 0
        if structural or score > 0:
            for line in lines[:25]:
                try:
                    parser.parse(line, ctx)
                except (ParseError, ValueError, TypeError):
                    continue
                except Exception:  # noqa: BLE001 - a buggy parser must not win
                    break
                parsed += 1
            score += parsed * _PARSE_WEIGHT
        parsed_counts[name] = parsed
        if score > 0:
            scores[name] = score

    if not scores:
        return DetectionResult("plaintext", 0.0, 0, len(lines), ())

    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))
    best_name, best_score = ranked[0]
    return DetectionResult(
        parser_name=best_name,
        score=best_score,
        parsed_lines=parsed_counts.get(best_name, 0),
        sample_size=len(lines),
        candidates=tuple(ranked[:5]),
    )


def get_parser(name: str) -> LogParser:
    """Resolve a parser by name, custom parsers included."""
    if name in custom_parsers:
        return custom_parsers[name]
    return parser_registry.create(name)


def sample_lines(path: Path, count: int = 25, *, encoding: str = "utf-8") -> list[str]:
    """Read up to ``count`` non-empty lines from the head of a file.

    Uses the shared safe opener so ``.gz`` is transparent and the decompressed
    stream is bounded.
    """
    from app.core.paths import open_stream

    lines: list[str] = []
    with open_stream(path, encoding=encoding, max_bytes=8 * 1024 * 1024) as stream:
        for line in stream:
            if line.strip():
                lines.append(line.rstrip("\r\n"))
            if len(lines) >= count:
                break
    return lines


__all__ = [
    "DetectionResult",
    "available_parsers",
    "detect_format",
    "get_parser",
    "sample_lines",
]
