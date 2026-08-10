"""Analytics, anomaly-detection, security-analysis and reporting integration tests."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.analytics import AnalyticsEngine, ReportBuilder, SecurityAnalyzer
from app.analytics.reports import render_html, render_json, render_markdown, save_report
from app.analytics.statistics import describe, iqr_bounds, moving_average, percentile, zscores
from app.anomaly_detection import (
    AnomalyService,
    DetectorConfig,
    EwmaDetector,
    IqrDetector,
    MovingAverageDetector,
    ZScoreDetector,
)
from app.core.config import Settings
from app.models.analytics import TimeSeries, TimeSeriesPoint
from app.models.enums import Severity
from app.models.log_event import LogEvent
from app.search import SearchService
from app.storage import ParquetStore

pytestmark = pytest.mark.integration


@pytest.fixture
def engine(settings: Settings, populated_store: Path) -> AnalyticsEngine:
    return AnalyticsEngine(settings=settings)


@pytest.fixture
def window(base_time: datetime) -> tuple[datetime, datetime]:
    return base_time - timedelta(hours=1), base_time + timedelta(hours=3)


class TestAnalyticsEngine:
    def test_overview(self, engine: AnalyticsEngine, window) -> None:
        overview = engine.overview(*window)
        assert overview.total_records == 200
        assert overview.total_errors == 50
        assert overview.error_rate == pytest.approx(0.25)
        assert overview.active_services == 4

    def test_errors_breakdowns(self, engine: AnalyticsEngine, window) -> None:
        errors = engine.errors(*window)
        assert errors.total_errors == 50
        assert errors.by_service
        assert sum(item.count for item in errors.by_service) == 50

    def test_status_code_distribution(self, engine: AnalyticsEngine, window) -> None:
        status = engine.status_codes(*window)
        assert status.by_class == {"2xx": 150, "5xx": 50}
        assert status.server_error_rate == pytest.approx(0.25)

    def test_latency_percentiles_are_ordered(self, engine: AnalyticsEngine, window) -> None:
        latency = engine.latency(*window)
        stats = latency.overall
        assert stats.minimum <= stats.median <= stats.p95 <= stats.p99 <= stats.maximum

    def test_traffic_top_lists(self, engine: AnalyticsEngine, window) -> None:
        traffic = engine.traffic(*window)
        assert traffic.total_requests == 200
        assert traffic.top_endpoints
        assert traffic.top_ips

    def test_service_health_classification(self, engine: AnalyticsEngine, window) -> None:
        services = engine.services(*window)
        assert len(services.services) == 4
        # The fixture makes every 4th record an error, so one service is 100 %
        # errors and the others are clean.
        assert any(service.status == "unhealthy" for service in services.services)

    def test_timeseries_is_gap_filled(self, engine: AnalyticsEngine, window) -> None:
        series = engine.timeseries("requests", *window, window="15m")
        assert len(series.points) > 1
        assert any(point.value == 0 for point in series.points)

    def test_filters_narrow_results(self, engine: AnalyticsEngine, window) -> None:
        filtered = engine.overview(*window, {"service": "api"})
        assert 0 < filtered.total_records < 200

    def test_unknown_metric_is_rejected(self, engine: AnalyticsEngine, window) -> None:
        with pytest.raises(ValueError, match="unknown metric"):
            engine.timeseries("not_a_metric", *window)

    def test_unknown_window_is_rejected(self, engine: AnalyticsEngine, window) -> None:
        with pytest.raises(ValueError, match="unsupported window"):
            engine.timeseries("requests", *window, window="3m")

    def test_empty_dataset_returns_zeroes(self, settings: Settings) -> None:
        empty = AnalyticsEngine(settings=settings)
        assert empty.overview().total_records == 0

    def test_distinct_values(self, engine: AnalyticsEngine, window) -> None:
        assert set(engine.distinct_values("service", *window)) == {
            "api",
            "auth",
            "payment",
            "search",
        }


class TestStatistics:
    def test_percentiles_interpolate(self) -> None:
        values = list(range(1, 101))
        assert percentile(values, 0.5) == pytest.approx(50.5)
        assert percentile(values, 0.95) == pytest.approx(95.05)

    def test_percentile_edge_cases(self) -> None:
        assert percentile([], 0.5) == 0.0
        assert percentile([7], 0.99) == 7.0

    def test_describe(self) -> None:
        stats = describe([1, 2, 3, 4, 5])
        assert stats.count == 5
        assert stats.average == 3.0
        assert stats.median == 3.0

    def test_zscores_handle_zero_variance(self) -> None:
        assert zscores([5, 5, 5]) == [0.0, 0.0, 0.0]

    def test_moving_average_is_trailing(self) -> None:
        assert moving_average([1, 2, 3, 4], 2) == [1.0, 1.5, 2.5, 3.5]

    def test_iqr_bounds_widen_with_the_multiplier(self) -> None:
        values = [1, 2, 3, 4, 5, 6, 7, 8, 100]
        narrow = iqr_bounds(values, 1.0)
        wide = iqr_bounds(values, 3.0)
        assert wide[1] > narrow[1]


def _series(values: list[float], metric: str = "errors") -> TimeSeries:
    from datetime import UTC

    start = datetime(2026, 8, 7, tzinfo=UTC)
    return TimeSeries(
        metric=metric,
        window="5m",
        points=[
            TimeSeriesPoint(bucket=start + timedelta(minutes=5 * i), value=value, count=int(value))
            for i, value in enumerate(values)
        ],
    )


class TestAnomalyDetectors:
    FLAT_WITH_SPIKE = [10.0] * 20 + [300.0] + [10.0] * 5

    def test_zscore_finds_the_spike(self) -> None:
        found = ZScoreDetector(DetectorConfig(threshold=2.5)).detect(_series(self.FLAT_WITH_SPIKE))
        assert found
        assert max(f.observed for f in found) == 300.0

    def test_moving_average_finds_the_spike(self) -> None:
        found = MovingAverageDetector(DetectorConfig(window=5)).detect(
            _series(self.FLAT_WITH_SPIKE)
        )
        assert any(f.observed == 300.0 for f in found)

    def test_iqr_finds_the_spike(self) -> None:
        assert IqrDetector().detect(_series(self.FLAT_WITH_SPIKE))

    def test_ewma_finds_the_spike(self) -> None:
        assert EwmaDetector(DetectorConfig(threshold=2.5)).detect(_series(self.FLAT_WITH_SPIKE))

    def test_no_anomalies_on_steady_data(self) -> None:
        steady = _series([10.0 + (i % 3) for i in range(40)])
        for detector in (ZScoreDetector(), MovingAverageDetector(), IqrDetector()):
            assert detector.detect(steady) == []

    def test_short_series_is_ignored(self) -> None:
        assert ZScoreDetector().detect(_series([1.0, 500.0])) == []

    def test_traffic_drops_are_reported(self) -> None:
        drop = _series([100.0] * 20 + [1.0] + [100.0] * 5, metric="requests")
        found = MovingAverageDetector(DetectorConfig(window=5)).detect(drop)
        assert any(f.type.value == "traffic_drop" for f in found)

    def test_error_drops_are_not_reported(self) -> None:
        """A drop in errors is good news, not an anomaly."""
        drop = _series([100.0] * 20 + [1.0] + [100.0] * 5, metric="errors")
        found = MovingAverageDetector(DetectorConfig(window=5)).detect(drop)
        assert all(f.observed >= f.expected for f in found)

    def test_severity_scales_with_magnitude(self) -> None:
        big = ZScoreDetector(DetectorConfig(threshold=2.0)).detect(_series([10.0] * 30 + [5_000.0]))
        assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in big)


class TestAnomalyService:
    def test_scan_deduplicates_across_detectors(
        self, settings: Settings, tmp_path: Path, base_time: datetime
    ) -> None:
        events: list[LogEvent] = []
        for minute in range(180):
            count = 40 if minute == 120 else 2  # one clear error spike
            for index in range(count):
                events.append(
                    LogEvent.build(
                        timestamp=base_time + timedelta(minutes=minute, seconds=index),
                        level="ERROR",
                        service="api",
                        message="boom",
                        status_code=500,
                        source="t",
                    )
                )
        store = ParquetStore(settings.processed_path)
        store.write(events, run_id="anom")
        store.flush()

        service = AnomalyService(AnalyticsEngine(settings=settings), settings)
        found = service.scan(
            base_time - timedelta(minutes=5),
            base_time + timedelta(hours=4),
            metrics=("errors",),
            window="5m",
        )
        assert found
        buckets = [anomaly.bucket for anomaly in found]
        assert len(buckets) == len(set(buckets))  # no duplicate buckets

    def test_disabled_detection_returns_nothing(
        self, settings: Settings, populated_store: Path
    ) -> None:
        disabled = settings.model_copy(
            update={
                "analytics": settings.analytics.model_copy(
                    update={"enable_anomaly_detection": False}
                )
            }
        )
        assert AnomalyService(settings=disabled).scan() == []


class TestSecurityAnalytics:
    @pytest.fixture
    def attack_store(self, settings: Settings, base_time: datetime) -> Path:
        events: list[LogEvent] = []
        for index in range(60):  # brute force + credential stuffing
            events.append(
                LogEvent.build(
                    timestamp=base_time + timedelta(seconds=index * 2),
                    level="WARNING",
                    service="auth",
                    message="authentication failed",
                    ip_address="198.51.100.9",
                    user_id=f"user{index}",
                    http_method="POST",
                    endpoint="/api/v1/auth/login",
                    status_code=401,
                    user_agent="sqlmap/1.8",
                    source="t",
                )
            )
        for index in range(40):  # endpoint scanning
            events.append(
                LogEvent.build(
                    timestamp=base_time + timedelta(seconds=index),
                    level="WARNING",
                    service="api",
                    message="not found",
                    ip_address="203.0.113.4",
                    http_method="GET",
                    endpoint=f"/.env{index}",
                    status_code=404,
                    source="t",
                )
            )
        store = ParquetStore(settings.processed_path)
        store.write(events, run_id="sec")
        store.flush()
        return settings.processed_path

    def test_detects_brute_force_and_stuffing(
        self, settings: Settings, attack_store: Path, base_time: datetime
    ) -> None:
        findings = SecurityAnalyzer(settings=settings).analyze(
            base_time - timedelta(hours=1), base_time + timedelta(hours=1)
        )
        kinds = {str(finding.type) for finding in findings}
        assert "brute_force" in kinds
        assert "credential_stuffing" in kinds
        assert "endpoint_scanning" in kinds

    def test_findings_carry_evidence_and_scores(
        self, settings: Settings, attack_store: Path, base_time: datetime
    ) -> None:
        findings = SecurityAnalyzer(settings=settings).analyze(
            base_time - timedelta(hours=1), base_time + timedelta(hours=1)
        )
        top = findings[0]
        assert 0 <= top.risk_score <= 100
        assert top.evidence
        assert top.event_count > 0

    def test_correlated_subjects_score_higher(
        self, settings: Settings, attack_store: Path, base_time: datetime
    ) -> None:
        findings = SecurityAnalyzer(settings=settings).analyze(
            base_time - timedelta(hours=1), base_time + timedelta(hours=1)
        )
        correlated = [f for f in findings if f.evidence.get("correlated_signals")]
        assert correlated

    def test_clean_data_produces_no_findings(
        self, settings: Settings, populated_store: Path, base_time: datetime
    ) -> None:
        findings = SecurityAnalyzer(settings=settings).analyze(
            base_time - timedelta(hours=1), base_time + timedelta(hours=3)
        )
        assert all(str(f.type) != "brute_force" for f in findings)

    def test_scoring_is_monotonic_in_volume(self) -> None:
        from app.analytics.security import score_finding
        from app.models.enums import SecurityFindingType

        low = score_finding(SecurityFindingType.BRUTE_FORCE, volume=10)
        high = score_finding(SecurityFindingType.BRUTE_FORCE, volume=10_000)
        assert high > low


class TestReports:
    def test_report_contains_every_section(
        self, settings: Settings, populated_store: Path, base_time: datetime
    ) -> None:
        report = ReportBuilder(settings).build(
            base_time - timedelta(hours=1), base_time + timedelta(hours=3)
        )
        assert report.overview.total_records == 200
        assert set(report.sections) == {
            "errors",
            "status_codes",
            "latency",
            "traffic",
            "services",
        }

    def test_renderers_produce_output(
        self, settings: Settings, populated_store: Path, base_time: datetime
    ) -> None:
        report = ReportBuilder(settings).build(
            base_time - timedelta(hours=1), base_time + timedelta(hours=3)
        )
        assert "# " in render_markdown(report)
        assert "<html>" in render_html(report)
        assert '"name"' in render_json(report)

    def test_report_can_be_saved_and_reloaded(
        self, settings: Settings, populated_store: Path, tmp_path: Path
    ) -> None:
        from app.analytics.reports import load_report

        report = ReportBuilder(settings).summary(hours=48)
        path = save_report(report, tmp_path / "reports", fmt="json")
        assert load_report(path).name == report.name


class TestSearchService:
    def test_query_language_end_to_end(self, settings: Settings, populated_store: Path) -> None:
        service = SearchService(settings=settings)
        result = service.search("level=ERROR", page_size=10, start=None, end=None)
        assert result.total == 50
        assert all(item["level"] == "ERROR" for item in result.items)

    def test_combined_predicates(self, settings: Settings, populated_store: Path) -> None:
        service = SearchService(settings=settings)
        result = service.search("service=api AND status_code>=500")
        assert result.total > 0

    def test_free_text_search(self, settings: Settings, populated_store: Path) -> None:
        result = SearchService(settings=settings).search("request 42")
        assert result.total >= 1

    def test_pagination_is_stable(self, settings: Settings, populated_store: Path) -> None:
        service = SearchService(settings=settings)
        first = service.search(page=1, page_size=10)
        second = service.search(page=2, page_size=10)
        assert first.items[0] != second.items[0]
        assert first.total == second.total

    def test_keyset_pagination(self, settings: Settings, populated_store: Path) -> None:
        from app.core.timeutil import parse_timestamp

        service = SearchService(settings=settings)
        page = service.search(page_size=5)
        cursor = parse_timestamp(page.items[-1]["timestamp"])
        following = service.search_after(
            after_timestamp=cursor, after_event_id=page.items[-1]["event_id"], page_size=5
        )
        assert following.items

    def test_get_by_id(self, settings: Settings, populated_store: Path) -> None:
        service = SearchService(settings=settings)
        first = service.search(page_size=1).items[0]
        assert service.get_by_id(first["event_id"])["event_id"] == first["event_id"]
        assert service.get_by_id("does-not-exist") is None

    def test_suggestions(self, settings: Settings, populated_store: Path) -> None:
        values = SearchService(settings=settings).suggest("service", "a")
        assert "api" in values and "auth" in values
