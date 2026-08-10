"""Unit tests for validation, transformation, deduplication and models."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.core.config import ValidationSettings
from app.core.masking import REDACTED, Masker
from app.core.timeutil import utcnow
from app.deduplication import (
    ContentHashStrategy,
    Deduplicator,
    EventIdStrategy,
    FieldsStrategy,
    NoDeduplication,
    SeenKeys,
)
from app.models.enums import HttpMethod, LogLevel, RejectReason, Severity
from app.models.log_event import LogEvent
from app.models.results import PipelineResult, RejectedRecord
from app.transformation.cleaning import RecordCleaner, clean_text, fix_mojibake
from app.transformation.enrichment import RecordEnricher
from app.transformation.normalization import (
    RecordNormalizer,
    classify_ip,
    infer_environment,
    normalise_service,
    template_endpoint,
    user_agent_family,
)
from app.validation import RecordValidator

pytestmark = pytest.mark.unit


class TestLogEvent:
    def test_event_id_is_deterministic(self, base_time: datetime) -> None:
        fields = {"timestamp": base_time, "message": "x", "service": "api", "source": "t"}
        assert LogEvent.build(**fields).event_id == LogEvent.build(**fields).event_id

    def test_ingest_time_does_not_affect_the_id(self, base_time: datetime) -> None:
        first = LogEvent.build(timestamp=base_time, message="x", ingested_at=base_time)
        second = LogEvent.build(
            timestamp=base_time, message="x", ingested_at=base_time + timedelta(hours=1)
        )
        assert first.event_id == second.event_id

    def test_level_aliases_are_coerced(self) -> None:
        event = LogEvent.build(timestamp=utcnow(), level="warn", message="x")
        assert event.level is LogLevel.WARNING

    def test_invalid_ip_is_dropped_not_raised(self) -> None:
        assert LogEvent.build(timestamp=utcnow(), ip_address="999.1.1.1").ip_address is None

    def test_forwarded_for_takes_the_client_address(self) -> None:
        event = LogEvent.build(timestamp=utcnow(), ip_address="192.0.2.5, 10.0.0.1")
        assert event.ip_address == "192.0.2.5"

    def test_unknown_fields_go_to_metadata(self) -> None:
        event = LogEvent.build(timestamp=utcnow(), message="x", tenant="acme")
        assert event.metadata["tenant"] == "acme"

    def test_metadata_is_bounded(self) -> None:
        event = LogEvent.build(timestamp=utcnow(), metadata={f"k{i}": i for i in range(500)})
        assert len(event.metadata) <= 64

    def test_is_error_covers_level_and_status(self) -> None:
        assert LogEvent.build(timestamp=utcnow(), level="ERROR").is_error
        assert LogEvent.build(timestamp=utcnow(), status_code=503).is_error
        assert not LogEvent.build(timestamp=utcnow(), status_code=200).is_error

    def test_status_class(self) -> None:
        assert LogEvent.build(timestamp=utcnow(), status_code=404).status_class == "4xx"

    def test_naive_timestamp_becomes_utc(self) -> None:
        event = LogEvent.build(timestamp=datetime(2026, 8, 7, 12), message="x")
        assert event.timestamp.tzinfo is not None

    def test_out_of_range_status_is_rejected_by_the_schema(self) -> None:
        with pytest.raises(ValueError):
            LogEvent(timestamp=utcnow(), status_code=999)

    def test_row_and_api_serialisation(self, sample_event: LogEvent) -> None:
        row = sample_event.to_row()
        assert isinstance(row["timestamp"], datetime)
        api = sample_event.to_api_dict()
        assert api["timestamp"].endswith("Z")
        assert isinstance(api["metadata"], dict)


class TestValidation:
    def test_valid_record_passes(self, sample_event: LogEvent) -> None:
        assert RecordValidator().validate(sample_event).valid

    def test_future_timestamp_is_rejected(self) -> None:
        event = LogEvent.build(timestamp=utcnow() + timedelta(hours=2), message="x")
        outcome = RecordValidator().validate(event)
        assert not outcome.valid
        assert outcome.fatal_issue is not None
        assert outcome.fatal_issue.reason is RejectReason.TIMESTAMP_OUT_OF_RANGE

    def test_small_clock_skew_is_tolerated(self) -> None:
        event = LogEvent.build(timestamp=utcnow() + timedelta(seconds=30), message="x")
        assert RecordValidator().validate(event).valid

    def test_oversized_message_is_rejected(self) -> None:
        settings = ValidationSettings(max_message_length=128)
        event = LogEvent.build(timestamp=utcnow(), message="x" * 500)
        outcome = RecordValidator(settings).validate(event)
        assert not outcome.valid
        assert outcome.fatal_issue is not None
        assert outcome.fatal_issue.reason is RejectReason.MESSAGE_TOO_LONG

    def test_empty_message_is_a_warning_by_default(self) -> None:
        outcome = RecordValidator().validate(LogEvent.build(timestamp=utcnow(), message=""))
        assert outcome.valid
        assert outcome.warnings

    def test_empty_message_is_fatal_when_required(self) -> None:
        settings = ValidationSettings(require_message=True)
        outcome = RecordValidator(settings).validate(LogEvent.build(timestamp=utcnow()))
        assert not outcome.valid

    def test_level_outside_the_allow_list_is_a_warning(self) -> None:
        # UNKNOWN is allowed by default (many formats carry no level at all),
        # so the allow-list has to be narrowed to exercise this rule.
        settings = ValidationSettings(allowed_levels=("INFO", "ERROR"))
        event = LogEvent.build(timestamp=utcnow(), level="bogus", message="x")
        outcome = RecordValidator(settings).validate(event)
        assert outcome.valid
        assert any(w.reason is RejectReason.INVALID_LEVEL for w in outcome.warnings)

    def test_validate_many_is_lazy(self, sample_events: list[LogEvent]) -> None:
        results = RecordValidator().validate_many(iter(sample_events))
        assert next(iter(results))[1].valid


class TestCleaning:
    def test_control_characters_and_ansi_are_stripped(self) -> None:
        assert clean_text("hello\x1b[31m \x00world\r\n") == "hello world"

    def test_empty_markers_become_none(self) -> None:
        for marker in ("-", "N/A", "null", "undefined", ""):
            assert clean_text(marker) is None

    def test_whitespace_is_collapsed(self) -> None:
        assert clean_text("a   \t  b") == "a b"

    def test_mojibake_is_repaired(self) -> None:
        assert fix_mojibake("cafÃ©") == "café"

    def test_non_mojibake_is_untouched(self) -> None:
        assert fix_mojibake("café") == "café"

    def test_cleaner_preserves_the_raw_message(self) -> None:
        event = LogEvent.build(
            timestamp=utcnow(), message="  dirty\x00 ", raw_message="  dirty\x00 "
        )
        cleaned = RecordCleaner().clean(event)
        assert cleaned.message == "dirty"
        assert cleaned.raw_message == event.raw_message

    def test_query_strings_are_stripped_from_endpoints(self) -> None:
        event = LogEvent.build(timestamp=utcnow(), endpoint="/a?token=secret")
        assert RecordCleaner().clean(event).endpoint == "/a"


class TestNormalization:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("Payment_API", "payment-api"), ("payment.api", "payment-api"), (None, None)],
    )
    def test_service_slugs(self, raw: str | None, expected: str | None) -> None:
        assert normalise_service(raw) == expected

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/api/v1/users/12345", "/api/v1/users/{id}"),
            ("/api/v1/users/8f2c1e40-1111-2222-3333-444455556666", "/api/v1/users/{uuid}"),
            ("/api/v1/users/someone@example.com", "/api/v1/users/{email}"),
            ("/api/v1/products", "/api/v1/products"),
            ("/", "/"),
        ],
    )
    def test_endpoint_templating(self, path: str, expected: str) -> None:
        assert template_endpoint(path) == expected

    @pytest.mark.parametrize(
        ("ip", "expected"),
        [
            ("127.0.0.1", "loopback"),
            ("10.0.0.5", "private"),
            # RFC 5737 documentation ranges are "private" to ipaddress, which
            # is what the security scoring relies on.
            ("192.0.2.5", "private"),
            ("8.8.8.8", "public"),
            ("not-an-ip", None),
        ],
    )
    def test_ip_classification(self, ip: str, expected: str | None) -> None:
        assert classify_ip(ip) == expected

    @pytest.mark.parametrize(
        ("ua", "family"),
        [
            ("Mozilla/5.0 ... Chrome/128 Safari/537", "Chrome"),
            ("Mozilla/5.0 ... Edg/128", "Edge"),
            ("curl/8.5.0", "curl"),
            ("sqlmap/1.8", "Other"),
            (None, None),
        ],
    )
    def test_user_agent_family(self, ua: str | None, family: str | None) -> None:
        assert user_agent_family(ua) == family

    def test_environment_inference(self) -> None:
        from app.models.enums import Environment

        assert infer_environment("api-prod-01") is Environment.PRODUCTION
        assert infer_environment("random-host") is Environment.UNKNOWN

    def test_normalizer_keeps_the_raw_endpoint(self) -> None:
        event = LogEvent.build(timestamp=utcnow(), endpoint="/users/42", service="API")
        normalised = RecordNormalizer().normalise(event)
        assert normalised.endpoint == "/users/{id}"
        assert normalised.metadata["endpoint_raw"] == "/users/42"
        assert normalised.service == "api"


class TestEnrichment:
    def test_secrets_in_messages_are_masked(self) -> None:
        event = LogEvent.build(timestamp=utcnow(), message="login password=hunter2")
        enriched = RecordEnricher(Masker()).enrich(event)
        assert "hunter2" not in enriched.message
        assert REDACTED in enriched.message
        assert enriched.metadata["masked"] is True

    def test_raw_message_is_masked_too(self) -> None:
        event = LogEvent.build(timestamp=utcnow(), message="ok", raw_message="api_key=abcdef123456")
        assert "abcdef123456" not in RecordEnricher(Masker()).enrich(event).raw_message

    def test_status_class_is_attached(self) -> None:
        event = LogEvent.build(timestamp=utcnow(), status_code=503)
        enriched = RecordEnricher(Masker()).enrich(event)
        assert enriched.metadata["status_class"] == "5xx"
        assert enriched.metadata["is_error"] is True

    def test_raw_message_can_be_dropped(self) -> None:
        event = LogEvent.build(timestamp=utcnow(), message="x", raw_message="a lot of text")
        assert RecordEnricher(Masker(), drop_raw_message=True).enrich(event).raw_message == ""


class TestDeduplication:
    def test_exact_duplicates_are_detected(self, sample_event: LogEvent) -> None:
        dedup = Deduplicator(ContentHashStrategy())
        assert not dedup.is_duplicate(sample_event)
        assert dedup.is_duplicate(sample_event)
        assert dedup.stats.duplicates == 1

    def test_event_id_strategy(self, sample_event: LogEvent) -> None:
        dedup = Deduplicator(EventIdStrategy())
        dedup.is_duplicate(sample_event)
        assert dedup.is_duplicate(sample_event.model_copy())

    def test_field_strategy_ignores_irrelevant_differences(self, base_time: datetime) -> None:
        dedup = Deduplicator(FieldsStrategy(("timestamp", "service", "message")))
        first = LogEvent.build(timestamp=base_time, service="api", message="same", request_id="a")
        second = LogEvent.build(timestamp=base_time, service="api", message="same", request_id="b")
        assert not dedup.is_duplicate(first)
        assert dedup.is_duplicate(second)

    def test_none_strategy_passes_everything(self, sample_event: LogEvent) -> None:
        dedup = Deduplicator(NoDeduplication())
        assert not dedup.is_duplicate(sample_event)
        assert not dedup.is_duplicate(sample_event)

    def test_filter_yields_only_first_occurrences(self, sample_event: LogEvent) -> None:
        dedup = Deduplicator(ContentHashStrategy())
        assert len(list(dedup.filter([sample_event] * 5))) == 1

    def test_field_strategy_requires_fields(self) -> None:
        with pytest.raises(ValueError):
            FieldsStrategy(())

    def test_seen_keys_evicts_the_oldest(self) -> None:
        seen = SeenKeys(max_size=2)
        seen.add("a")
        seen.add("b")
        seen.add("c")
        assert len(seen) == 2
        assert seen.evictions == 1
        assert "a" not in seen

    def test_snapshot_reports_strategy_and_counters(self, sample_event: LogEvent) -> None:
        dedup = Deduplicator(ContentHashStrategy())
        dedup.is_duplicate(sample_event)
        snapshot = dedup.snapshot()
        assert snapshot["strategy"] == "content_hash"
        assert snapshot["unique"] == 1


class TestResults:
    def test_rejected_record_hashes_its_payload(self) -> None:
        record = RejectedRecord(raw="broken line", reason=RejectReason.UNPARSEABLE)
        assert len(record.raw_hash) == 32

    def test_pipeline_result_rates(self) -> None:
        result = PipelineResult(run_id="r1", lines_read=1_000, records_parsed=900)
        for _ in range(100):
            result.record_rejection(RejectReason.UNPARSEABLE)
        assert result.records_rejected == 100
        assert result.rejection_rate == pytest.approx(0.1)
        assert result.summary()["run_id"] == "r1"

    def test_merge_accumulates(self) -> None:
        a = PipelineResult(run_id="a", lines_read=10, records_written=8)
        b = PipelineResult(run_id="b", lines_read=5, records_written=5, succeeded=False)
        a.merge(b)
        assert a.lines_read == 15
        assert a.records_written == 13
        assert a.succeeded is False


class TestEnums:
    def test_severity_from_score(self) -> None:
        assert Severity.from_score(95) is Severity.CRITICAL
        assert Severity.from_score(75) is Severity.HIGH
        assert Severity.from_score(50) is Severity.MEDIUM
        assert Severity.from_score(5) is Severity.INFO

    def test_level_ordering(self) -> None:
        assert LogLevel.ERROR.severity > LogLevel.WARNING.severity
        assert LogLevel.CRITICAL.is_error
        assert not LogLevel.INFO.is_error

    def test_http_method_coercion(self) -> None:
        assert HttpMethod.coerce("post") is HttpMethod.POST
        assert HttpMethod.coerce("BREW") is HttpMethod.OTHER
        assert HttpMethod.coerce(None) is None
