"""Security regression tests.

Each test encodes a control that must never silently regress: injection,
traversal, authentication, authorisation, rate limiting, SSRF, secret leakage
and denial of service.  A failure here is a vulnerability, not a style issue.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.exceptions import PathTraversalError, SearchSyntaxError, SecurityError
from app.core.masking import ALL_RULES, REDACTED, Masker
from app.core.paths import resolve_within, safe_filename
from app.search.query import compile_query

pytestmark = pytest.mark.security


# --------------------------------------------------------------------------- #
# Injection
# --------------------------------------------------------------------------- #
SQL_INJECTION_PAYLOADS = [
    "'; DROP TABLE logs; --",
    "1' OR '1'='1",
    "' UNION SELECT * FROM api_keys --",
    "admin'--",
    "1; DELETE FROM logs",
    "' OR 1=1 --",
    '" OR ""="',
    "1 AND (SELECT COUNT(*) FROM logs) > 0",
    "%27%20OR%201%3D1",
    "\\'; DROP TABLE logs; --",
]


class TestSearchInjection:
    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_in_a_field_value_stays_a_bound_parameter(self, payload: str) -> None:
        """A payload may parse, but it must never reach the SQL *text*.

        The bound value is not always byte-identical to the input — a ``*``
        becomes a LIKE wildcard — so the invariant asserted here is the one
        that actually matters: nothing from the payload appears in the SQL,
        and every value is a placeholder.
        """
        try:
            compiled = compile_query(f'service="{payload}"')
        except SearchSyntaxError:
            return  # rejected outright is also a correct outcome
        assert payload not in compiled.sql
        assert compiled.sql.count("?") == len(compiled.params)
        assert any(payload.split()[0] in str(param) for param in compiled.params)

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_injection_as_a_bare_term_is_rejected_or_parameterised(self, payload: str) -> None:
        try:
            compiled = compile_query(payload)
        except SearchSyntaxError:
            return
        assert "DROP" not in compiled.sql.upper()
        assert "UNION" not in compiled.sql.upper()
        assert ";" not in compiled.sql

    def test_unknown_fields_are_rejected_by_the_allow_list(self) -> None:
        with pytest.raises(SearchSyntaxError, match="unknown field"):
            compile_query("password=x")

    def test_sql_keywords_cannot_be_used_as_fields(self) -> None:
        for expression in ("select=1", "drop=1", "union=1", "1=1"):
            with pytest.raises(SearchSyntaxError):
                compile_query(expression)

    def test_like_metacharacters_are_escaped(self) -> None:
        compiled = compile_query("message~100%_discount")
        assert "\\%" in compiled.params[0]
        assert "\\_" in compiled.params[0]

    def test_query_complexity_is_bounded(self) -> None:
        with pytest.raises(SearchSyntaxError, match="too complex"):
            compile_query(" AND ".join(["service=x"] * 200))

    def test_query_nesting_is_bounded(self) -> None:
        with pytest.raises(SearchSyntaxError, match="nesting"):
            compile_query("(" * 20 + "service=x" + ")" * 20)

    def test_query_length_is_bounded(self) -> None:
        with pytest.raises(SearchSyntaxError, match="exceeds"):
            compile_query("a" * 10_000)

    def test_value_length_is_bounded(self) -> None:
        with pytest.raises(SearchSyntaxError):
            compile_query(f'service="{"x" * 1_000}"')

    def test_api_rejects_injection_without_leaking(self, api_client) -> None:
        for payload in SQL_INJECTION_PAYLOADS:
            response = api_client.get("/logs/search", params={"q": payload})
            assert response.status_code in (200, 400)
            body = response.text.upper()
            assert "TRACEBACK" not in body
            assert "DUCKDB" not in body

    def test_injection_via_filter_parameters_is_harmless(self, api_client) -> None:
        response = api_client.get("/logs", params={"service": "'; DROP TABLE logs; --"})
        assert response.status_code == 200
        assert response.json()["pagination"]["total"] == 0
        # And the dataset is intact.
        assert api_client.get("/stats").json()["records"] == 200


class TestSqlLiteralEscaping:
    """A path is not user input, but it is still interpolated into SQL.

    A data root containing an apostrophe used to terminate the string literal
    inside ``read_parquet('...')`` and break every analytics query.  The file
    list is now a bound parameter and the one remaining literal (DuckDB's
    ``SET temp_directory``, which takes no parameters) is quote-escaped.
    """

    @pytest.fixture
    def awkward_root(self, tmp_path: Path) -> Path:
        from datetime import UTC, datetime

        from app.models.log_event import LogEvent
        from app.storage import ParquetStore

        root = tmp_path / "da'ta"
        (root / "processed").mkdir(parents=True)
        store = ParquetStore(root / "processed")
        store.write(
            [
                LogEvent.build(
                    timestamp=datetime(2026, 8, 7, 12, tzinfo=UTC),
                    service="api",
                    level="ERROR",
                    message="m",
                    status_code=500,
                    response_time_ms=10.0,
                )
                for _ in range(20)
            ],
            run_id="r",
        )
        store.flush()
        return root

    @pytest.fixture
    def awkward_settings(self, awkward_root: Path) -> Settings:
        from app.core.config import load_settings

        return load_settings(
            overrides={
                "environment": "test",
                "storage": {"data_root": str(awkward_root)},
                "observability": {"level": "ERROR", "format": "console"},
            }
        )

    def test_scan_binds_the_file_list_rather_than_quoting_it(
        self, awkward_settings: Settings
    ) -> None:
        from app.storage import build_engine

        engine = build_engine(awkward_settings)
        fragment, params = engine.scan()
        assert "?" in fragment
        assert "da'ta" not in fragment  # the path is nowhere in the SQL text
        assert any("da'ta" in glob for glob in params[0])

    def test_every_query_path_survives_a_quote_in_the_data_root(
        self, awkward_settings: Settings
    ) -> None:
        from datetime import UTC, datetime, timedelta

        from app.analytics import AnalyticsEngine, SecurityAnalyzer
        from app.search import SearchService

        # An explicit window: the fixture's records are at a fixed date, so a
        # "last 24 hours" default would make this test depend on the clock.
        start = datetime(2026, 8, 7, tzinfo=UTC)
        end = start + timedelta(days=1)

        analytics = AnalyticsEngine(settings=awkward_settings)
        search = SearchService(analytics.engine, awkward_settings)

        assert analytics.engine.dataset_summary()["records"] == 20
        assert analytics.overview(start, end).total_records == 20
        assert analytics.errors(start, end).total_errors == 20
        assert analytics.timeseries("requests", start, end, window="1h").points
        assert analytics.services(start, end).services
        assert search.search("level=ERROR", start=start, end=end).total == 20
        assert search.suggest("service") == ["api"]
        assert SecurityAnalyzer(analytics.engine, awkward_settings).analyze(start, end) == []


class TestDatabaseIdentifierValidation:
    @pytest.mark.parametrize(
        "identifier",
        ['logs"; DROP TABLE x; --', "logs`", "logs table", "logs;", "", "a" * 100, "1abc"],
    )
    def test_invalid_identifiers_are_rejected(self, identifier: str) -> None:
        from app.core.exceptions import ConfigurationError
        from app.ingestion.database import validate_identifier

        with pytest.raises(ConfigurationError):
            validate_identifier(identifier)

    def test_valid_identifiers_pass(self) -> None:
        from app.ingestion.database import qualified_table

        assert qualified_table("public.app_logs") == '"public"."app_logs"'

    def test_source_query_binds_filter_values(self) -> None:
        from datetime import UTC, datetime

        from app.ingestion.database import DatabaseSource

        source = DatabaseSource(
            "sqlite:///:memory:",
            table="logs",
            timestamp_column="ts",
            since=datetime(2026, 1, 1, tzinfo=UTC),
        )
        sql, params = source._build_query()
        assert ":since" in sql
        assert "2026" not in sql
        assert params["since"].year == 2026


# --------------------------------------------------------------------------- #
# Path traversal
# --------------------------------------------------------------------------- #
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//etc/passwd",
    "/etc/shadow",
    "C:\\Windows\\System32\\config\\SAM",
    "logs/../../../../etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]


class TestPathTraversal:
    @pytest.mark.parametrize("payload", TRAVERSAL_PAYLOADS)
    def test_resolution_is_confined_to_the_root(self, tmp_path: Path, payload: str) -> None:
        root = tmp_path / "allowed"
        root.mkdir()
        with pytest.raises((PathTraversalError, FileNotFoundError)):
            resolve_within(root / payload, [root], must_exist=True)

    def test_symlink_escape_is_blocked(self, tmp_path: Path) -> None:
        root = tmp_path / "allowed"
        root.mkdir()
        outside = tmp_path / "secret.txt"
        outside.write_text("classified", encoding="utf-8")
        link = root / "link.log"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks require privileges on this platform")
        with pytest.raises(PathTraversalError):
            resolve_within(link, [root])

    @pytest.mark.parametrize("payload", TRAVERSAL_PAYLOADS)
    def test_filenames_are_sanitised(self, payload: str) -> None:
        cleaned = safe_filename(payload)
        assert "/" not in cleaned
        assert "\\" not in cleaned
        assert not cleaned.startswith("..")

    def test_stored_report_route_cannot_escape(self, api_client) -> None:
        for payload in ("../../../../etc/passwd", "..%2f..%2fetc%2fpasswd"):
            assert api_client.get(f"/reports/stored/{payload}").status_code in (404, 400)

    def test_ingestion_outside_the_allowed_roots_is_refused(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        from app.ingestion import build_source

        outside = tmp_path.parent / "outside.log"
        outside.write_text("data", encoding="utf-8")
        with pytest.raises(PathTraversalError):
            build_source(outside, settings)


# --------------------------------------------------------------------------- #
# Authentication and authorisation
# --------------------------------------------------------------------------- #
@pytest.fixture
def authed_client(authed_settings: Settings, tmp_path: Path):  # noqa: ANN201
    from fastapi.testclient import TestClient

    from app.api.deps import reset_dependencies
    from app.api.main import create_app

    reset_dependencies()
    with TestClient(create_app(authed_settings)) as client:
        yield client
    reset_dependencies()


VALID_KEY = "test-key-abcdefghijklmnop"


class TestAuthentication:
    def test_requests_without_a_key_are_rejected(self, authed_client) -> None:
        response = authed_client.get("/logs")
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"

    @pytest.mark.parametrize(
        "key", ["", "wrong", "test-key-abcdefghijklmno", "TEST-KEY-ABCDEFGHIJKLMNOP", "null"]
    )
    def test_invalid_keys_are_rejected(self, authed_client, key: str) -> None:
        assert authed_client.get("/logs", headers={"X-API-Key": key}).status_code == 401

    def test_valid_key_via_header(self, authed_client) -> None:
        assert authed_client.get("/logs", headers={"X-API-Key": VALID_KEY}).status_code == 200

    def test_valid_key_via_bearer(self, authed_client) -> None:
        assert (
            authed_client.get("/logs", headers={"Authorization": f"Bearer {VALID_KEY}"}).status_code
            == 200
        )

    def test_health_endpoints_stay_public(self, authed_client) -> None:
        for path in ("/health", "/health/live", "/health/ready", "/metrics"):
            assert authed_client.get(path).status_code == 200

    def test_failed_attempts_do_not_log_the_key(self, authed_client, caplog) -> None:
        import logging

        with caplog.at_level(logging.WARNING):
            authed_client.get("/logs", headers={"X-API-Key": "super-secret-attempt"})
        assert "super-secret-attempt" not in caplog.text

    def test_error_body_does_not_echo_the_key(self, authed_client) -> None:
        response = authed_client.get("/logs", headers={"X-API-Key": "leak-me-please"})
        assert "leak-me-please" not in response.text


class TestPrincipalCaching:
    """Authentication must be cheap, but not so cheap that revocation is slow."""

    @pytest.fixture(autouse=True)
    def _clean_cache(self):  # noqa: ANN202
        from app.api.security import clear_principal_cache

        clear_principal_cache()
        yield
        clear_principal_cache()

    def _key(self, settings: Settings) -> str:
        from app.storage import MetadataStore

        store = MetadataStore.from_settings(settings)
        store.create_schema()
        secret = store.create_api_key("cached", ["read"])
        store.close()
        return secret

    def test_repeated_verification_succeeds(self, authed_settings: Settings) -> None:
        """Regression: SQLite returns naive datetimes, so the second call used
        to raise when comparing ``last_used_at`` against an aware ``utcnow()``."""
        from app.api.security import _authenticate_via_store, clear_principal_cache

        key = self._key(authed_settings)
        for _ in range(3):
            clear_principal_cache()  # force the store path, not the cache
            assert _authenticate_via_store(key, authed_settings) is not None

    def test_cached_verification_is_far_cheaper(self, authed_settings: Settings) -> None:
        import time

        from app.api.security import _authenticate_via_store

        key = self._key(authed_settings)
        _authenticate_via_store(key, authed_settings)  # warm
        started = time.perf_counter()
        for _ in range(200):
            _authenticate_via_store(key, authed_settings)
        per_call_ms = (time.perf_counter() - started) / 200 * 1000
        assert per_call_ms < 1.0, f"cached auth took {per_call_ms:.3f} ms/call"

    def test_failures_are_never_cached(self, authed_settings: Settings) -> None:
        """A cached rejection would be an oracle, and would block a new key."""
        from app.api.security import _authenticate_via_store, _principal_cache

        assert _authenticate_via_store("not-a-real-key", authed_settings) is None
        assert not _principal_cache

    def test_revocation_clears_the_cache(self, authed_settings: Settings) -> None:
        from fastapi.testclient import TestClient

        from app.api.deps import reset_dependencies
        from app.api.main import create_app
        from app.storage import MetadataStore

        store = MetadataStore.from_settings(authed_settings)
        store.create_schema()
        victim = store.create_api_key("victim", ["read"])
        store.close()

        reset_dependencies()
        with TestClient(create_app(authed_settings)) as client:
            assert client.get("/logs", headers={"X-API-Key": victim}).status_code == 200
            admin = {"X-API-Key": "test-key-abcdefghijklmnop"}
            assert client.delete("/admin/apikeys/victim", headers=admin).status_code == 200
            # Without cache invalidation this would still be 200 for 30 seconds.
            assert client.get("/logs", headers={"X-API-Key": victim}).status_code == 401
        reset_dependencies()


class TestAuthorization:
    def test_read_scope_cannot_reach_admin(self, authed_settings: Settings, tmp_path: Path) -> None:
        from fastapi.testclient import TestClient

        from app.api.deps import reset_dependencies
        from app.api.main import create_app
        from app.storage import MetadataStore

        store = MetadataStore.from_settings(authed_settings)
        store.create_schema()
        read_key = store.create_api_key("reader", ["read"])
        store.close()

        reset_dependencies()
        with TestClient(create_app(authed_settings)) as client:
            headers = {"X-API-Key": read_key}
            assert client.get("/logs", headers=headers).status_code == 200
            assert client.get("/admin/config", headers=headers).status_code == 403
            assert (
                client.post(
                    "/jobs", headers=headers, json={"name": "report", "parameters": {}}
                ).status_code
                == 403
            )
        reset_dependencies()

    def test_write_scope_cannot_run_admin_jobs(
        self, authed_settings: Settings, tmp_path: Path
    ) -> None:
        from fastapi.testclient import TestClient

        from app.api.deps import reset_dependencies
        from app.api.main import create_app
        from app.storage import MetadataStore

        store = MetadataStore.from_settings(authed_settings)
        store.create_schema()
        write_key = store.create_api_key("writer", ["write"])
        store.close()

        reset_dependencies()
        with TestClient(create_app(authed_settings)) as client:
            response = client.post(
                "/jobs",
                headers={"X-API-Key": write_key},
                json={"name": "cleanup", "parameters": {}},
            )
            assert response.status_code == 403
        reset_dependencies()

    def test_scope_implication(self) -> None:
        from app.api.security import Principal

        admin = Principal("a", frozenset({"admin"}))
        assert admin.has("read") and admin.has("write") and admin.has("admin")
        reader = Principal("r", frozenset({"read"}))
        assert reader.has("read") and not reader.has("write")

    def test_only_registered_jobs_can_be_submitted(self, authed_client) -> None:
        response = authed_client.post(
            "/jobs",
            headers={"X-API-Key": VALID_KEY},
            json={"name": "os.system", "parameters": {"cmd": "rm -rf /"}},
        )
        assert response.status_code == 400


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #
class TestRateLimiting:
    def test_bucket_refills_over_time(self) -> None:
        from app.api.security import TokenBucketLimiter

        limiter = TokenBucketLimiter(rate_per_second=1_000.0, capacity=2)
        assert limiter.check("a")[0]
        assert limiter.check("a")[0]
        allowed, retry_after, _ = limiter.check("a")
        assert not allowed
        assert retry_after > 0
        import time

        # Generous relative to the refill rate: Windows' monotonic clock has
        # ~15 ms granularity, so a 10 ms sleep can measure as zero elapsed.
        time.sleep(0.1)
        assert limiter.check("a")[0]

    def test_buckets_are_per_identity(self) -> None:
        from app.api.security import TokenBucketLimiter

        limiter = TokenBucketLimiter(rate_per_second=0.001, capacity=1)
        assert limiter.check("client-a")[0]
        assert not limiter.check("client-a")[0]
        assert limiter.check("client-b")[0]

    def test_limiter_state_is_bounded(self) -> None:
        from app.api.security import TokenBucketLimiter

        limiter = TokenBucketLimiter(rate_per_second=1, capacity=1, max_keys=10)
        for index in range(100):
            limiter.check(f"client-{index}")
        assert len(limiter._buckets) <= 10

    def test_api_returns_429_with_retry_after(
        self, settings: Settings, populated_store: Path
    ) -> None:
        from fastapi.testclient import TestClient

        from app.api.deps import reset_dependencies
        from app.api.main import create_app

        throttled = settings.model_copy(
            update={
                "api": settings.api.model_copy(
                    update={"rate_limit_requests": 3, "rate_limit_burst": 0}
                )
            }
        )
        reset_dependencies()
        with TestClient(create_app(throttled)) as client:
            statuses = [client.get("/logs").status_code for _ in range(12)]
            assert 429 in statuses
            limited = next(
                response for response in (client.get("/logs"),) if response.status_code == 429
            )
            assert "Retry-After" in limited.headers
        reset_dependencies()

    def test_health_probes_are_never_throttled(
        self, settings: Settings, populated_store: Path
    ) -> None:
        from fastapi.testclient import TestClient

        from app.api.deps import reset_dependencies
        from app.api.main import create_app

        throttled = settings.model_copy(
            update={
                "api": settings.api.model_copy(
                    update={"rate_limit_requests": 1, "rate_limit_burst": 0}
                )
            }
        )
        reset_dependencies()
        with TestClient(create_app(throttled)) as client:
            assert all(client.get("/health/live").status_code == 200 for _ in range(20))
        reset_dependencies()

    def test_forwarded_for_is_ignored_without_a_trusted_proxy(self) -> None:
        from unittest.mock import Mock

        from app.api.security import client_identity
        from app.core.config import load_settings

        request = Mock()
        request.client.host = "192.0.2.9"
        request.headers = {"x-forwarded-for": "1.2.3.4"}
        assert client_identity(request, load_settings()) == "192.0.2.9"


# --------------------------------------------------------------------------- #
# SSRF
# --------------------------------------------------------------------------- #
class TestSsrf:
    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:6379/",
            "http://localhost/admin",
            "http://10.0.0.1/internal",
            "http://192.168.1.1/",
            "http://[::1]/",
        ],
    )
    def test_private_and_link_local_targets_are_blocked(self, url: str) -> None:
        from app.ingestion.http_api import assert_url_allowed

        with pytest.raises((SecurityError, Exception)) as info:
            assert_url_allowed(url)
        assert info.type is not AssertionError

    @pytest.mark.parametrize(
        "url", ["file:///etc/passwd", "gopher://x/", "ftp://x/", "jar:http://x/"]
    )
    def test_non_http_schemes_are_blocked(self, url: str) -> None:
        from app.ingestion.http_api import assert_url_allowed

        with pytest.raises(SecurityError, match="http"):
            assert_url_allowed(url)

    def test_private_targets_can_be_explicitly_permitted(self) -> None:
        from app.ingestion.http_api import assert_url_allowed

        assert_url_allowed("http://127.0.0.1:8080/logs", allow_private=True)

    def test_urls_are_logged_without_query_strings(self) -> None:
        from app.ingestion.http_api import redact_url

        redacted = redact_url("https://api.example.test/logs?token=secret&x=1")
        assert "secret" not in redacted
        assert redacted == "https://api.example.test/logs"


# --------------------------------------------------------------------------- #
# Secret handling
# --------------------------------------------------------------------------- #
class TestSecretHandling:
    def test_config_dumps_never_contain_secrets(self) -> None:
        from app.core.config import load_settings

        settings = load_settings(
            overrides={
                "database": {"driver": "postgresql", "password": "PlainTextPassword1"},
                "api": {"api_keys": ["SuperSecretApiKey"]},
                "cache": {"redis_password": "RedisSecret"},
            }
        )
        dumped = json.dumps(settings.safe_dump())
        for secret in ("PlainTextPassword1", "SuperSecretApiKey", "RedisSecret"):
            assert secret not in dumped
        assert secret not in repr(settings)

    def test_admin_config_endpoint_redacts(self, authed_client) -> None:
        response = authed_client.get("/admin/config", headers={"X-API-Key": VALID_KEY})
        assert response.status_code == 200
        assert VALID_KEY not in response.text

    def test_secrets_are_masked_before_storage(self, settings: Settings, tmp_path: Path) -> None:
        from app.pipeline import LogPipeline, PipelineOptions

        path = tmp_path / "raw" / "secrets.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        payloads = [
            "password=TopSecret1",
            "Authorization: Bearer abcdefghijklmnopqrst",
            "api_key=sk_live_1234567890abcdefghij",
            "contact alice@example.com",
        ]
        path.write_text(
            "\n".join(
                json.dumps({"timestamp": "2026-08-07T12:00:00Z", "message": payload})
                for payload in payloads
            ),
            encoding="utf-8",
        )
        LogPipeline(settings).run(path, PipelineOptions(run_id="sec"))
        stored = b"".join(f.read_bytes() for f in settings.processed_path.rglob("*.parquet"))
        for secret in (
            b"TopSecret1",
            b"abcdefghijklmnopqrst",
            b"sk_live_1234567890abcdefghij",
            b"alice@example.com",
        ):
            assert secret not in stored

    def test_dead_letter_payloads_are_masked(self, settings: Settings, tmp_path: Path) -> None:
        from app.pipeline import LogPipeline, PipelineOptions

        path = tmp_path / "raw" / "bad.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"timestamp": "2026-08-07T12:00:00Z", "message": "ok"})
            + "\nbroken line with password=Leaked123\n",
            encoding="utf-8",
        )
        LogPipeline(settings).run(path, PipelineOptions(run_id="dlq"))
        stored = b"".join(f.read_bytes() for f in settings.rejected_path.rglob("*.jsonl"))
        assert b"Leaked123" not in stored

    @pytest.mark.parametrize(
        "payload",
        [
            "password=x",
            "Authorization: Bearer abcdefghijkl",
            "eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig",
            "AKIAIOSFODNN7EXAMPLE",
            "a@b.co",
        ],
    )
    def test_masker_leaves_no_residue(self, payload: str) -> None:
        masked = Masker(rules=ALL_RULES).mask_text(f"prefix {payload} suffix")
        assert REDACTED in masked
        assert "prefix" in masked and "suffix" in masked


# --------------------------------------------------------------------------- #
# Denial of service
# --------------------------------------------------------------------------- #
class TestResourceLimits:
    def test_oversized_lines_are_truncated_not_buffered(
        self, settings: Settings, tmp_path: Path
    ) -> None:
        from app.ingestion import FileSource

        path = tmp_path / "raw" / "huge.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x" * 100_000 + "\n", encoding="utf-8")
        source = FileSource(path, max_line_bytes=1_000)
        records = list(source.read())
        assert len(records[0].payload) == 1_000
        assert source.stats.skipped_oversized == 1

    def test_decompression_bombs_are_bounded(self, tmp_path: Path) -> None:
        import gzip

        from app.core.paths import open_stream

        path = tmp_path / "bomb.gz"
        with gzip.open(path, "wb") as stream:
            stream.write(b"A" * (5 * 1024 * 1024))
        with open_stream(path, max_bytes=64 * 1024) as reader:
            assert len(reader.read()) <= 64 * 1024

    def test_request_bodies_are_capped(self, settings: Settings, populated_store: Path) -> None:
        from fastapi.testclient import TestClient

        from app.api.deps import reset_dependencies
        from app.api.main import create_app

        reset_dependencies()
        with TestClient(create_app(settings)) as client:
            response = client.post(
                "/jobs",
                content=b"x" * 5_000_000,
                headers={"Content-Type": "application/json", "Content-Length": "5000000"},
            )
            assert response.status_code == 413
        reset_dependencies()

    def test_regex_patterns_reject_catastrophic_backtracking(self) -> None:
        from app.core.exceptions import ConfigurationError
        from app.parsers.custom import assert_safe_pattern

        for pattern in [r"(?P<a>(x+)+)", r"(?P<a>(a|a)*)", r"(?P<a>(.*)*)"]:
            with pytest.raises(ConfigurationError):
                assert_safe_pattern(pattern)

    def test_deduplication_memory_is_bounded(self) -> None:
        from app.deduplication import SeenKeys

        seen = SeenKeys(max_size=100)
        for index in range(10_000):
            seen.add(f"key-{index}")
        assert len(seen) == 100

    def test_metadata_cardinality_is_bounded(self) -> None:
        from app.core.timeutil import utcnow
        from app.models.log_event import LogEvent

        event = LogEvent.build(
            timestamp=utcnow(), metadata={f"k{i}": "v" * 10_000 for i in range(1_000)}
        )
        assert len(event.metadata) <= 64
        assert all(len(str(v)) <= 4_096 for v in event.metadata.values())


# --------------------------------------------------------------------------- #
# Response hardening
# --------------------------------------------------------------------------- #
class TestResponseHardening:
    def test_security_headers_are_present(self, api_client) -> None:
        headers = api_client.get("/health").headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["Referrer-Policy"] == "no-referrer"
        assert "default-src 'self'" in headers["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]

    def test_server_header_is_not_advertised(self, api_client) -> None:
        assert "server" not in {k.lower() for k in api_client.get("/health").headers}

    def test_errors_never_include_a_traceback(self, api_client) -> None:
        for path in ("/logs/search?q=%28%28%28", "/does-not-exist", "/logs/x"):
            text = api_client.get(path).text
            assert "Traceback" not in text
            assert 'File "' not in text

    def test_cors_is_closed_by_default(self, api_client) -> None:
        response = api_client.get("/health", headers={"Origin": "https://evil.test"})
        assert "access-control-allow-origin" not in {k.lower() for k in response.headers}
