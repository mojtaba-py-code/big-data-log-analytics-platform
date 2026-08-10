"""Parsing layer.

Importing this package registers every built-in parser.  Adding a format means
adding a module here and decorating the class with
``@parser_registry.register(...)`` — no other file changes.
"""

from __future__ import annotations

from app.parsers.access import AccessLogParser
from app.parsers.base import LogParser, ParseContext, parser_registry
from app.parsers.custom import (
    CustomParserSpec,
    RegexParser,
    build_custom_parsers,
    clear_custom_parsers,
    custom_parsers,
)
from app.parsers.detector import DetectionResult, detect_format, get_parser, sample_lines
from app.parsers.structured import (
    CsvRowParser,
    JsonLineParser,
    KeyValueParser,
    StructuredParser,
)
from app.parsers.text import NginxErrorLogParser, PlainTextParser, SyslogParser

__all__ = [
    "AccessLogParser",
    "CsvRowParser",
    "CustomParserSpec",
    "DetectionResult",
    "JsonLineParser",
    "KeyValueParser",
    "LogParser",
    "NginxErrorLogParser",
    "ParseContext",
    "PlainTextParser",
    "RegexParser",
    "StructuredParser",
    "SyslogParser",
    "build_custom_parsers",
    "clear_custom_parsers",
    "custom_parsers",
    "detect_format",
    "get_parser",
    "parser_registry",
    "sample_lines",
]
