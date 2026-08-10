"""Anomaly detection service.

Runs the configured detectors across the metrics that matter, de-duplicates
their findings and ranks them.

Why several detectors at once
-----------------------------
Each detector has a blind spot (see :mod:`app.anomaly_detection.detectors`).
Running two or three and merging their output catches more real incidents; the
cost is duplicate findings for the same bucket, which :func:`deduplicate`
collapses by keeping the highest-severity, highest-scoring one and recording
how many detectors agreed.  Agreement is itself signal: an anomaly found by
three independent methods is far less likely to be noise.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final

from app.analytics.engine import AnalyticsEngine
from app.anomaly_detection.detectors import (
    AnomalyDetector,
    DetectorConfig,
    build_detectors,
)
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.models.analytics import Anomaly, TimeSeries
from app.models.enums import Severity

log = get_logger(__name__)

#: Metrics scanned by default — the ones that map to an operator's questions:
#: is it broken, is it slow, is it under unusual load?
DEFAULT_METRICS: Final[tuple[str, ...]] = (
    "errors",
    "server_errors",
    "latency_p95",
    "requests",
)

_SEVERITY_ORDER: Final[dict[Severity, int]] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def deduplicate(anomalies: Sequence[Anomaly]) -> list[Anomaly]:
    """Collapse findings that describe the same (metric, bucket, dimension)."""
    best: dict[tuple[str, str, str | None], Anomaly] = {}
    agreement: dict[tuple[str, str, str | None], set[str]] = {}
    for anomaly in anomalies:
        key = (anomaly.metric, anomaly.bucket.isoformat(), anomaly.dimension)
        agreement.setdefault(key, set()).add(anomaly.detector)
        current = best.get(key)
        if current is None or _rank(anomaly) > _rank(current):
            best[key] = anomaly

    merged: list[Anomaly] = []
    for key, anomaly in best.items():
        detectors = sorted(agreement[key])
        if len(detectors) > 1:
            anomaly = anomaly.model_copy(
                update={
                    "detector": "+".join(detectors),
                    "description": f"{anomaly.description} (agreed by {len(detectors)} detectors)",
                }
            )
        merged.append(anomaly)
    return sorted(merged, key=_sort_key)


def _rank(anomaly: Anomaly) -> tuple[int, float]:
    return (_SEVERITY_ORDER.get(anomaly.severity, 0), anomaly.score)


def _sort_key(anomaly: Anomaly) -> tuple[int, float, str]:
    """Most severe first, then strongest score, then chronological."""
    severity, score = _rank(anomaly)
    return (-severity, -score, anomaly.bucket.isoformat())


class AnomalyService:
    """Scans metrics for anomalies over a time window."""

    def __init__(
        self,
        analytics: AnalyticsEngine | None = None,
        settings: Settings | None = None,
        detectors: Sequence[AnomalyDetector] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.analytics = analytics or AnalyticsEngine(settings=self.settings)
        config = DetectorConfig(
            threshold=self.settings.analytics.zscore_threshold,
            window=self.settings.analytics.moving_average_window,
            min_history=self.settings.analytics.min_history_points,
            iqr_multiplier=self.settings.analytics.iqr_multiplier,
        )
        self.detectors = list(detectors or build_detectors(("moving_average", "iqr"), config))

    def scan(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        *,
        metrics: Sequence[str] = DEFAULT_METRICS,
        window: str | None = None,
        filters: Mapping[str, Any] | None = None,
        min_severity: Severity = Severity.LOW,
        limit: int = 200,
    ) -> list[Anomaly]:
        """Detect anomalies across ``metrics`` in one pass."""
        if not self.settings.analytics.enable_anomaly_detection:
            return []
        bucket = window or self.settings.analytics.default_window
        found: list[Anomaly] = []
        for metric in metrics:
            series = self.analytics.timeseries(
                metric, start, end, filters, window=bucket, fill_gaps=True
            )
            found.extend(self._scan_series(series))
        result = [
            anomaly
            for anomaly in deduplicate(found)
            if _SEVERITY_ORDER[anomaly.severity] >= _SEVERITY_ORDER[min_severity]
        ]
        log.info(
            "anomaly scan complete",
            extra={"metrics": list(metrics), "window": bucket, "anomalies": len(result)},
        )
        return result[:limit]

    def scan_by_dimension(
        self,
        dimension: str = "service",
        start: datetime | None = None,
        end: datetime | None = None,
        *,
        metric: str = "errors",
        window: str | None = None,
        max_dimensions: int = 20,
        min_severity: Severity = Severity.MEDIUM,
    ) -> list[Anomaly]:
        """Per-service (or per-endpoint) scan.

        A platform-wide series hides a single failing service inside healthy
        aggregate traffic; scanning each dimension separately is what surfaces
        it.  Bounded by ``max_dimensions`` because this is N queries.
        """
        bucket = window or self.settings.analytics.default_window
        values = self.analytics.distinct_values(dimension, start, end, limit=max_dimensions)
        found: list[Anomaly] = []
        for value in values:
            series = self.analytics.timeseries(
                metric, start, end, {dimension: value}, window=bucket
            )
            found.extend(self._scan_series(series, dimension=f"{dimension}={value}"))
        return [
            anomaly
            for anomaly in deduplicate(found)
            if _SEVERITY_ORDER[anomaly.severity] >= _SEVERITY_ORDER[min_severity]
        ]

    def _scan_series(self, series: TimeSeries, *, dimension: str | None = None) -> list[Anomaly]:
        results: list[Anomaly] = []
        for detector in self.detectors:
            try:
                results.extend(detector.detect(series, dimension=dimension))
            except Exception:  # noqa: BLE001 - one bad detector must not stop the scan
                log.exception("detector failed", extra={"detector": detector.name})
        return results


__all__ = ["DEFAULT_METRICS", "AnomalyService", "deduplicate"]
