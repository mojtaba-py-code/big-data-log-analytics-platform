"""Parser unit tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.core.exceptions import ParseError
from app.models.enums import HttpMethod, LogLevel
from app.parsers import ParseContext, detect_format, get_parser, parser_registry
from app.parsers.access import AccessLogParser, _split_request
from app.parsers.base import coerce_duration_ms, coerce_int, map_structured_record, normalise_key
from app.parsers.custom import CustomParserSpec, RegexParser, assert_safe_pattern
from app.parsers.structured import JsonLineParser, KeyValueParser, flatten
from app.parsers.text import NginxErrorLogParser, PlainTextParser, SyslogParser

pytestmark = pytest.mark.unit


@pytest.fixture
def ctx() -> ParseContext:
    return ParseContext(source="test", default_service="svc")


class TestJsonParser:
    def test_parses_flat_record(self, ctx: ParseContext) -> None:
        event = JsonLineParser().parse(
            '{"timestamp":"2026-08-07T12:00:00Z","level":"ERROR",'
            '"service":"payment","message":"boom"}',
            ctx,
        )
        assert event.level is LogLevel.ERROR
        assert event.service == "payment"
        assert event.message == "boom"
        assert event.timestamp == datetime(2026, 8, 7, 12, 0, tzinfo=UTC)

    def test_flattens_nested_http_object(self, ctx: ParseContext) -> None:
        event = JsonLineParser().parse(
            '{"timestamp":"2026-08-07T12:00:00Z","msg":"ok",'
            '"http":{"method":"post","path":"/x","status":201,"duration_ms":12.5}}',
            ctx,
        )
        assert event.http_method is HttpMethod.POST
        assert event.endpoint == "/x"
        assert event.status_code == 201
        assert event.response_time_ms == 12.5

    def test_unmapped_fields_are_preserved_in_metadata(self, ctx: ParseContext) -> None:
        event = JsonLineParser().parse(
            '{"timestamp":"2026-08-07T12:00:00Z","message":"x","tenant":"acme"}', ctx
        )
        assert event.metadata["tenant"] == "acme"

    def test_invalid_json_raises_parse_error(self, ctx: ParseContext) -> None:
        with pytest.raises(ParseError):
            JsonLineParser().parse("{not json", ctx)

    def test_json_array_is_rejected(self, ctx: ParseContext) -> None:
        with pytest.raises(ParseError):
            JsonLineParser().parse("[1, 2, 3]", ctx)

    def test_raw_message_is_the_original_line(self, ctx: ParseContext) -> None:
        line = '{"timestamp":"2026-08-07T12:00:00Z","message":"x"}'
        assert JsonLineParser().parse(line, ctx).raw_message == line


class TestAccessLogParser:
    COMBINED = (
        "192.0.2.1 - alice [07/Aug/2026:12:00:00 +0000] "
        '"GET /api/v1/users?token=secret HTTP/1.1" 200 1043 '
        '"https://example.test/" "Mozilla/5.0" 0.523'
    )

    def test_parses_combined_format(self, ctx: ParseContext) -> None:
        event = AccessLogParser().parse(self.COMBINED, ctx)
        assert event.ip_address == "192.0.2.1"
        assert event.http_method is HttpMethod.GET
        assert event.status_code == 200
        assert event.bytes_sent == 1043
        assert event.user_id == "alice"
        assert event.user_agent == "Mozilla/5.0"

    def test_query_string_is_stripped_from_endpoint(self, ctx: ParseContext) -> None:
        # Keeps secrets out of aggregate tables and keeps cardinality sane.
        assert AccessLogParser().parse(self.COMBINED, ctx).endpoint == "/api/v1/users"

    def test_trailing_request_time_is_seconds(self, ctx: ParseContext) -> None:
        assert AccessLogParser().parse(self.COMBINED, ctx).response_time_ms == 523.0

    def test_common_format_without_referrer(self, ctx: ParseContext) -> None:
        line = '192.0.2.9 - - [07/Aug/2026:12:00:00 +0000] "GET / HTTP/1.1" 404 0'
        event = AccessLogParser().parse(line, ctx)
        assert event.status_code == 404
        assert event.level is LogLevel.WARNING
        assert event.user_id is None

    def test_status_class_maps_to_level(self, ctx: ParseContext) -> None:
        line = '192.0.2.9 - - [07/Aug/2026:12:00:00 +0000] "GET / HTTP/1.1" 503 0'
        assert AccessLogParser().parse(line, ctx).level is LogLevel.ERROR

    def test_non_access_line_raises(self, ctx: ParseContext) -> None:
        with pytest.raises(ParseError):
            AccessLogParser().parse("just some text", ctx)

    @pytest.mark.parametrize(
        ("request_line", "expected_path"),
        [
            ("GET /a/b HTTP/1.1", "/a/b"),
            ("GET /a%2Fb HTTP/1.1", "/a/b"),
            ("GET /%252e%252e/etc HTTP/1.1", "/%2e%2e/etc"),  # decoded once only
            ("GET / HTTP/1.1", "/"),
        ],
    )
    def test_request_line_splitting(self, request_line: str, expected_path: str) -> None:
        _, path, _ = _split_request(request_line)
        assert path == expected_path

    def test_control_characters_are_stripped_from_path(self) -> None:
        _, path, _ = _split_request("GET /a\r\nInjected: header HTTP/1.1")
        assert "\r" not in (path or "") and "\n" not in (path or "")


class TestPlainTextParser:
    def test_timestamp_level_message(self, ctx: ParseContext) -> None:
        event = PlainTextParser().parse("2026-08-07 12:00:00 ERROR database is down", ctx)
        assert event.level is LogLevel.ERROR
        assert event.message == "database is down"
        assert event.timestamp.hour == 12

    def test_logger_in_brackets(self, ctx: ParseContext) -> None:
        event = PlainTextParser().parse(
            "2026-08-07 12:00:00 INFO [payment.handler] order created", ctx
        )
        assert event.logger == "payment.handler"
        assert event.message == "order created"

    def test_inline_key_values_are_promoted(self, ctx: ParseContext) -> None:
        event = PlainTextParser().parse(
            "2026-08-07 12:00:00 INFO done status=201 duration=45ms request_id=abc", ctx
        )
        assert event.status_code == 201
        assert event.response_time_ms == 45.0
        assert event.request_id == "abc"

    def test_missing_timestamp_is_inferred_and_flagged(self, ctx: ParseContext) -> None:
        event = PlainTextParser().parse("ERROR something broke", ctx)
        assert event.metadata.get("timestamp_inferred") is True

    def test_empty_line_raises(self, ctx: ParseContext) -> None:
        with pytest.raises(ParseError):
            PlainTextParser().parse("   ", ctx)


class TestSyslogParser:
    def test_rfc3164_priority_maps_to_level(self, ctx: ParseContext) -> None:
        event = SyslogParser().parse(
            "<34>Aug  7 12:00:00 host1 sshd[1234]: Failed password for root", ctx
        )
        assert event.level is LogLevel.CRITICAL  # 34 % 8 == 2
        assert event.hostname == "host1"
        assert event.service == "sshd"

    def test_rfc5424(self, ctx: ParseContext) -> None:
        event = SyslogParser().parse(
            "<165>1 2026-08-07T12:00:00Z host app 1234 ID47 - message here", ctx
        )
        assert event.service == "app"
        assert event.message == "message here"

    def test_non_syslog_raises(self, ctx: ParseContext) -> None:
        with pytest.raises(ParseError):
            SyslogParser().parse("2026-08-07 ERROR nope", ctx)


class TestNginxErrorParser:
    LINE = (
        "2026/08/07 12:00:00 [error] 29#29: *1 open() failed, "
        'client: 192.0.2.5, server: api, request: "GET /missing HTTP/1.1"'
    )

    def test_extracts_client_and_request(self, ctx: ParseContext) -> None:
        event = NginxErrorLogParser().parse(self.LINE, ctx)
        assert event.level is LogLevel.ERROR
        assert event.ip_address == "192.0.2.5"
        assert event.endpoint == "/missing"
        assert event.hostname == "api"


class TestKeyValueParser:
    def test_logfmt(self, ctx: ParseContext) -> None:
        event = KeyValueParser().parse(
            'ts=2026-08-07T12:00:00Z level=error service=api msg="it broke" duration=12ms', ctx
        )
        assert event.level is LogLevel.ERROR
        assert event.message == "it broke"
        assert event.response_time_ms == 12.0

    def test_too_few_pairs_raises(self, ctx: ParseContext) -> None:
        with pytest.raises(ParseError):
            KeyValueParser().parse("just text", ctx)


class TestFieldMapping:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("X-Request-ID", "x_request_id"),
            ("request.id", "request_id"),
            ("requestId", "request_id"),
            ("HTTP_USER_AGENT", "http_user_agent"),
            ("already_snake", "already_snake"),
        ],
    )
    def test_key_normalisation(self, raw: str, expected: str) -> None:
        assert normalise_key(raw) == expected

    def test_aliases_map_to_canonical_fields(self) -> None:
        mapped = map_structured_record(
            {"ts": "2026-08-07T12:00:00Z", "msg": "hi", "remote_addr": "192.0.2.1"}
        )
        assert mapped["message"] == "hi"
        assert mapped["ip_address"] == "192.0.2.1"
        assert mapped["timestamp"].year == 2026

    def test_out_of_range_status_goes_to_metadata(self) -> None:
        mapped = map_structured_record({"status": 999, "message": "x"})
        assert "status_code" not in mapped
        assert mapped["metadata"]["status_code_raw"] == 999

    @pytest.mark.parametrize(
        ("value", "field", "expected"),
        [
            (12.5, "duration_ms", 12.5),
            (0.523, "request_time", 523.0),
            (150, "duration", 150.0),
            ("12ms", None, 12.0),
            ("1.5s", None, 1500.0),
            (0.25, "duration", 250.0),
            (None, None, None),
            ("-", None, None),
            (True, None, None),
        ],
    )
    def test_duration_units(self, value: object, field: str | None, expected: float | None) -> None:
        assert coerce_duration_ms(value, field) == expected

    def test_coerce_int_rejects_junk(self) -> None:
        assert coerce_int("abc") is None
        assert coerce_int("42") == 42

    def test_flatten_exposes_leaf_and_dotted_names(self) -> None:
        flat = flatten({"http": {"status": 500}})
        assert flat["http_status"] == 500
        assert flat["status"] == 500


class TestDetection:
    @pytest.mark.parametrize(
        ("sample", "expected"),
        [
            (['{"timestamp":"2026-08-07T12:00:00Z","message":"x"}'], "json"),
            (
                ['192.0.2.1 - - [07/Aug/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 5'],
                "access",
            ),
            (["<34>Aug  7 12:00:00 h sshd[1]: failed"], "syslog"),
            (["2026-08-07 12:00:00 ERROR boom"], "plaintext"),
        ],
    )
    def test_detects_expected_format(self, sample: list[str], expected: str) -> None:
        assert detect_format(sample, filename="x.log").parser_name == expected

    def test_empty_sample_falls_back_to_plaintext(self) -> None:
        assert detect_format([]).parser_name == "plaintext"

    def test_every_registered_parser_is_constructible(self) -> None:
        for name in parser_registry.names():
            assert get_parser(name) is not None


class TestCustomParser:
    SPEC = CustomParserSpec(
        name="pipe-format",
        pattern=r"^(?P<timestamp>\S{1,40}) \| (?P<level>\w{1,10}) \| (?P<service>\w{1,30}) \| (?P<message>.{0,500})$",  # noqa: E501 - a realistic single-line pattern
    )

    def test_parses_configured_format(self, ctx: ParseContext) -> None:
        event = RegexParser(self.SPEC).parse(
            "2026-08-07T12:00:00Z | ERROR | payment | charge failed", ctx
        )
        assert event.level is LogLevel.ERROR
        assert event.service == "payment"
        assert event.message == "charge failed"

    def test_non_matching_line_raises(self, ctx: ParseContext) -> None:
        with pytest.raises(ParseError):
            RegexParser(self.SPEC).parse("nope", ctx)

    def test_rejects_nested_quantifier(self) -> None:
        from app.core.exceptions import ConfigurationError

        with pytest.raises(ConfigurationError, match="nested"):
            assert_safe_pattern(r"^(?P<x>(a+)+)$")

    def test_rejects_pattern_without_named_groups(self) -> None:
        from app.core.exceptions import ConfigurationError

        with pytest.raises(ConfigurationError, match="named groups"):
            assert_safe_pattern(r"^\d+$")

    def test_rejects_oversized_pattern(self) -> None:
        from app.core.exceptions import ConfigurationError

        with pytest.raises(ConfigurationError, match="too long"):
            assert_safe_pattern("(?P<x>a)" + "b" * 5_000)
