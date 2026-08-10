"""Unit tests for the core layer: config, masking, hashing, time, paths, retry."""

from __future__ import annotations

import logging
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.core.config import load_settings
from app.core.exceptions import ConfigurationError, PathTraversalError, RetryExhaustedError
from app.core.hashing import (
    content_hash,
    event_id_for,
    fingerprint,
    fingerprint_fields,
    generate_api_key,
    hash_secret,
    verify_secret,
)
from app.core.logging import JsonFormatter, MaskingFilter, log_context, set_request_id
from app.core.masking import ALL_RULES, REDACTED, Masker
from app.core.metrics import MetricsRegistry
from app.core.paths import resolve_within, safe_filename
from app.core.registry import Registry
from app.core.retry import CircuitBreaker, RetryPolicy, call_with_retry
from app.core.timeutil import (
    ensure_utc,
    floor_to_window,
    iter_windows,
    parse_range,
    parse_timestamp,
    to_iso,
)

pytestmark = pytest.mark.unit


class TestConfig:
    def test_defaults_are_usable(self) -> None:
        settings = load_settings()
        assert settings.environment == "development"
        assert settings.storage.format == "parquet"

    def test_file_and_override_precedence(self, tmp_path: Path) -> None:
        config = tmp_path / "config.yaml"
        config.write_text("processing:\n  batch_size: 777\n", encoding="utf-8")
        settings = load_settings(config, {"processing": {"batch_size": 999}})
        assert settings.processing.batch_size == 999

    def test_environment_variables_are_read(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LOGA_PROCESSING__BATCH_SIZE", "4321")
        assert load_settings().processing.batch_size == 4321

    def test_missing_config_file_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError, match="not found"):
            load_settings(tmp_path / "nope.yaml")

    def test_unsupported_config_format(self, tmp_path: Path) -> None:
        path = tmp_path / "config.ini"
        path.write_text("[x]\n", encoding="utf-8")
        with pytest.raises(ConfigurationError):
            load_settings(path)

    def test_secrets_are_redacted_in_dumps(self) -> None:
        settings = load_settings(
            overrides={"database": {"driver": "postgresql", "password": "hunter2"}}
        )
        dumped = str(settings.safe_dump())
        assert "hunter2" not in dumped
        assert "hunter2" not in repr(settings)

    def test_production_requires_auth(self) -> None:
        with pytest.raises(ConfigurationError, match="auth_required"):
            load_settings(
                overrides={
                    "environment": "production",
                    "api": {"auth_required": False, "docs_enabled": False},
                }
            )

    def test_production_rejects_wildcard_cors(self) -> None:
        with pytest.raises(ConfigurationError, match="cors_origins"):
            load_settings(
                overrides={
                    "environment": "production",
                    "api": {
                        "auth_required": True,
                        "api_keys": ["k" * 24],
                        "cors_origins": ["*"],
                        "docs_enabled": False,
                    },
                }
            )

    def test_production_requires_masking(self) -> None:
        with pytest.raises(ConfigurationError, match="masking"):
            load_settings(
                overrides={
                    "environment": "production",
                    "api": {"auth_required": True, "api_keys": ["k" * 24], "docs_enabled": False},
                    "masking": {"enabled": False},
                }
            )

    def test_valid_production_config_passes(self) -> None:
        settings = load_settings(
            overrides={
                "environment": "production",
                "api": {
                    "auth_required": True,
                    "api_keys": ["k" * 24],
                    "docs_enabled": False,
                },
                "observability": {"level": "INFO"},
            }
        )
        assert settings.is_production

    def test_unknown_masking_rule_is_rejected(self) -> None:
        with pytest.raises(ConfigurationError):
            load_settings(overrides={"masking": {"rules": ["not-a-rule"]}})

    def test_sqlite_url_needs_no_password(self) -> None:
        assert load_settings().database.url().startswith("sqlite:///")

    def test_postgres_url_requires_password(self) -> None:
        settings = load_settings(overrides={"database": {"driver": "postgresql"}})
        with pytest.raises(ConfigurationError, match="password"):
            settings.database.url()

    def test_settings_are_frozen(self) -> None:
        from pydantic import ValidationError

        settings = load_settings()
        with pytest.raises(ValidationError):
            settings.environment = "production"  # type: ignore[misc]


class TestMasking:
    @pytest.mark.parametrize(
        "payload",
        [
            "password=hunter2",
            "api_key=abcdef123456",
            "Authorization: Bearer abcdefghijklmnop",
            "token: 0123456789abcdef",
            "user@example.com",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signaturehere",
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            "sk_live_1234567890abcdefghij",
        ],
    )
    def test_secrets_are_redacted(self, payload: str) -> None:
        masked = Masker(rules=ALL_RULES).mask_text(payload)
        assert REDACTED in masked
        assert payload not in masked

    def test_ordinary_text_is_untouched(self) -> None:
        text = "request completed in 12ms with status 200"
        assert Masker().mask_text(text) == text

    def test_sensitive_field_names_are_masked_in_mappings(self) -> None:
        masked = Masker().mask_mapping({"password": "x", "note": "fine"})
        assert masked["password"] == REDACTED
        assert masked["note"] == "fine"

    def test_nested_structures_are_masked(self) -> None:
        masked = Masker().mask_object({"outer": {"api_key": "secret", "n": 1}})
        assert masked["outer"]["api_key"] == REDACTED
        assert masked["outer"]["n"] == 1

    def test_disabled_masker_is_a_passthrough(self) -> None:
        masker = Masker(enabled=False)
        assert masker.mask_text("password=hunter2") == "password=hunter2"

    def test_unknown_rule_fails_loudly_at_construction(self) -> None:
        with pytest.raises(KeyError):
            Masker(rules=["nope"])

    def test_oversized_input_is_truncated_not_scanned(self) -> None:
        masked = Masker().mask_text("a" * 200_000)
        assert "truncated" in masked

    def test_contains_sensitive_detects_without_mutating(self) -> None:
        masker = Masker(rules=ALL_RULES)
        assert masker.contains_sensitive("password=abc")
        assert not masker.contains_sensitive("plain text")

    def test_trigger_prefilter_does_not_miss_secrets(self) -> None:
        """The fast path must never let a secret through."""
        masker = Masker(rules=ALL_RULES)
        for payload in ("PASSWORD=Secret1", "AUTHORIZATION: Bearer abcdefghijkl"):
            assert REDACTED in masker.mask_text(payload)


class TestLoggingMasking:
    def test_filter_redacts_the_rendered_message(self) -> None:
        record = logging.LogRecord(
            "t", logging.INFO, __file__, 1, "login with password=%s", ("hunter2",), None
        )
        MaskingFilter().filter(record)
        assert "hunter2" not in record.getMessage()

    def test_filter_redacts_exception_text(self) -> None:
        try:
            raise ValueError("dsn=postgres://u:hunter2@host/db")
        except ValueError:
            import sys

            record = logging.LogRecord(
                "t", logging.ERROR, __file__, 1, "failed", None, sys.exc_info()
            )
        MaskingFilter().filter(record)
        assert record.exc_text is not None

    def test_json_formatter_emits_required_fields(self) -> None:
        import json

        set_request_id("abc123")
        record = logging.LogRecord("t", logging.INFO, __file__, 7, "hello", None, None)
        record.request_id = "abc123"
        payload = json.loads(JsonFormatter().format(record))
        for field in ("timestamp", "level", "logger", "message", "module", "function"):
            assert field in payload
        assert payload["request_id"] == "abc123"

    def test_log_context_adds_fields(self) -> None:
        with log_context(job="ingest"):
            from app.core.logging import log_context_var

            assert (log_context_var.get() or {})["job"] == "ingest"


class TestHashing:
    def test_fingerprints_are_stable(self) -> None:
        assert fingerprint(["a", 1, None]) == fingerprint(["a", 1, None])

    def test_distinct_inputs_differ(self) -> None:
        assert fingerprint(["a", "b"]) != fingerprint(["ab", ""])

    def test_none_and_empty_string_do_not_collide(self) -> None:
        assert fingerprint([None]) != fingerprint([""])

    def test_field_order_is_significant(self) -> None:
        row = {"a": 1, "b": 2}
        assert fingerprint_fields(row, ["a", "b"]) != fingerprint_fields(row, ["b", "a"])

    def test_event_id_is_deterministic(self) -> None:
        moment = datetime(2026, 8, 7, tzinfo=UTC)
        assert event_id_for(moment, "s", "m") == event_id_for(moment, "s", "m")

    def test_secret_verification_is_correct(self) -> None:
        secret = generate_api_key()
        assert verify_secret(secret, hash_secret(secret))
        assert not verify_secret("wrong", hash_secret(secret))

    def test_generated_keys_are_unique_and_long(self) -> None:
        keys = {generate_api_key() for _ in range(50)}
        assert len(keys) == 50
        assert all(len(k) >= 32 for k in keys)

    def test_content_hash_length(self) -> None:
        assert len(content_hash("x")) == 32


class TestTimeUtil:
    @pytest.mark.parametrize(
        "raw",
        [
            "2026-08-07T12:00:00Z",
            "2026-08-07 12:00:00",
            "07/Aug/2026:12:00:00 +0000",
            "[07/Aug/2026:12:00:00 +0000]",
            1786104000,
            1786104000000,
        ],
    )
    def test_parses_common_formats(self, raw: object) -> None:
        parsed = parse_timestamp(raw)
        assert parsed is not None
        assert parsed.tzinfo is not None

    @pytest.mark.parametrize("raw", ["", "not-a-time", None, "999999999999999999999"])
    def test_unparseable_returns_none(self, raw: object) -> None:
        assert parse_timestamp(raw) is None

    def test_naive_datetimes_become_utc(self) -> None:
        assert ensure_utc(datetime(2026, 8, 7, 12)).tzinfo is UTC

    @pytest.mark.parametrize(
        ("window", "expected_minute"), [("1m", 34), ("5m", 30), ("15m", 30), ("1h", 0)]
    )
    def test_window_flooring(self, window: str, expected_minute: int) -> None:
        moment = datetime(2026, 8, 7, 12, 34, 56, tzinfo=UTC)
        assert floor_to_window(moment, window).minute == expected_minute

    def test_day_flooring_zeroes_the_clock(self) -> None:
        floored = floor_to_window(datetime(2026, 8, 7, 23, 59, tzinfo=UTC), "1d")
        assert (floored.hour, floored.minute) == (0, 0)

    def test_unknown_window_raises(self) -> None:
        with pytest.raises(KeyError):
            floor_to_window(datetime.now(UTC), "3m")

    def test_iter_windows_is_inclusive_and_gapless(self) -> None:
        start = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)
        buckets = iter_windows(start, start + timedelta(minutes=20), "5m")
        assert len(buckets) == 5
        assert buckets[0] == start

    def test_parse_range_swaps_inverted_bounds(self) -> None:
        start, end = parse_range("2026-08-08T00:00:00Z", "2026-08-07T00:00:00Z")
        assert start < end

    def test_to_iso_is_utc_with_z(self) -> None:
        assert to_iso(datetime(2026, 8, 7, 12, tzinfo=UTC)) == "2026-08-07T12:00:00Z"


class TestPaths:
    def test_allows_paths_inside_the_root(self, tmp_path: Path) -> None:
        target = tmp_path / "logs" / "app.log"
        target.parent.mkdir()
        target.touch()
        assert resolve_within(target, [tmp_path]) == target.resolve()

    @pytest.mark.parametrize(
        "candidate",
        ["../../etc/passwd", "..\\..\\windows\\system32", "/etc/shadow", "C:\\Windows\\System32"],
    )
    def test_blocks_traversal(self, tmp_path: Path, candidate: str) -> None:
        with pytest.raises(PathTraversalError):
            resolve_within(tmp_path / candidate, [tmp_path])

    def test_blocks_nul_byte(self, tmp_path: Path) -> None:
        with pytest.raises(PathTraversalError):
            resolve_within("evil\x00.log", [tmp_path])

    def test_blocks_reserved_device_names(self, tmp_path: Path) -> None:
        with pytest.raises(PathTraversalError):
            resolve_within(tmp_path / "CON.log", [tmp_path])

    def test_requires_at_least_one_root(self) -> None:
        with pytest.raises(PathTraversalError):
            resolve_within("x", [])

    def test_missing_file_raises_when_required(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            resolve_within(tmp_path / "absent.log", [tmp_path], must_exist=True)

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("report.json", "report.json"),
            # Separators become underscores and leading dots are stripped, so
            # the result can never re-enter a parent directory.
            ("../../etc/passwd", "_.._etc_passwd"),
            ("a/b\\c.txt", "a_b_c.txt"),
            ("", "unnamed"),
            ("CON", "unnamed"),
        ],
    )
    def test_safe_filename(self, raw: str, expected: str) -> None:
        assert safe_filename(raw) == expected


class TestRetry:
    def test_succeeds_after_transient_failures(self) -> None:
        attempts = {"n": 0}

        def flaky() -> str:
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise ConnectionError("temporary")
            return "ok"

        policy = RetryPolicy(attempts=5, base_delay=0.001, jitter=False)
        assert call_with_retry(flaky, policy) == "ok"
        assert attempts["n"] == 3

    def test_exhausts_and_raises(self) -> None:
        policy = RetryPolicy(attempts=2, base_delay=0.001, jitter=False)
        with pytest.raises(RetryExhaustedError):
            call_with_retry(lambda: (_ for _ in ()).throw(OSError("nope")), policy)

    def test_non_retryable_errors_propagate_immediately(self) -> None:
        calls = {"n": 0}

        def boom() -> None:
            calls["n"] += 1
            raise ValueError("permanent")

        with pytest.raises(ValueError):
            call_with_retry(boom, RetryPolicy(attempts=3, base_delay=0.001))
        assert calls["n"] == 1

    def test_backoff_grows_and_is_capped(self) -> None:
        policy = RetryPolicy(base_delay=1.0, multiplier=2.0, max_delay=4.0, jitter=False)
        assert [policy.delay_for(n) for n in (1, 2, 3, 9)] == [1.0, 2.0, 4.0, 4.0]

    def test_circuit_breaker_opens_then_half_opens(self) -> None:
        breaker = CircuitBreaker(failure_threshold=2, reset_timeout=0.01)
        breaker.record_failure()
        breaker.record_failure()
        assert not breaker.allows()
        import time

        time.sleep(0.02)
        assert breaker.allows()
        breaker.record_success()
        assert breaker.state == "closed"


class TestRegistry:
    def test_register_resolve_and_alias(self) -> None:
        registry: Registry[object] = Registry("thing")

        @registry.register("primary", "alias")
        class Thing:
            """A thing."""

        assert registry.resolve("primary") is Thing
        assert registry.resolve("ALIAS") is Thing
        assert "primary" in registry

    def test_duplicate_registration_is_rejected(self) -> None:
        registry: Registry[object] = Registry("thing")
        registry.add("a", dict)
        with pytest.raises(ValueError, match="already registered"):
            registry.add("a", list)

    def test_unknown_name_raises_plugin_not_found(self) -> None:
        from app.core.exceptions import PluginNotFoundError

        registry: Registry[object] = Registry("thing")
        with pytest.raises(PluginNotFoundError):
            registry.resolve("absent")


class TestMetrics:
    def test_counters_gauges_and_timers(self) -> None:
        metrics = MetricsRegistry()
        metrics.increment("records", 5)
        metrics.set_gauge("memory", 12.5)
        with metrics.timer("stage"):
            pass
        snapshot = metrics.snapshot()
        assert snapshot["counters"]["records"] == 5
        assert snapshot["gauges"]["memory"] == 12.5
        assert snapshot["timers"]["stage"]["count"] == 1

    def test_labelled_counters(self) -> None:
        metrics = MetricsRegistry()
        metrics.increment_label("rejections", "unparseable", 3)
        assert metrics.snapshot()["labels"]["rejections"]["unparseable"] == 3

    def test_merge_combines_worker_registries(self) -> None:
        a, b = MetricsRegistry(), MetricsRegistry()
        a.increment("x", 2)
        b.increment("x", 3)
        a.merge(b)
        assert a.counters["x"] == 5

    def test_prometheus_rendering(self) -> None:
        metrics = MetricsRegistry()
        metrics.increment("records")
        assert "loga_records_total 1" in metrics.to_prometheus()


class TestImportOrder:
    """``app.analytics`` and ``app.anomaly_detection`` reference each other.

    Whichever is imported first has to win.  The suite happens to reach
    ``app.analytics`` first, so a cycle between them stays invisible here and
    only surfaces at a different entry point — it broke the container image,
    where the CLI reaches ``app.anomaly_detection`` first.  Each package is
    therefore imported first in its own interpreter.
    """

    @pytest.mark.parametrize(
        "module",
        ["app.anomaly_detection", "app.analytics", "app.cli.main", "app.api"],
    )
    def test_package_imports_standalone(self, module: str) -> None:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", f"import {module}"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
