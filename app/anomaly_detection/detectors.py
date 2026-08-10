"""Statistical anomaly detectors.

Responsibility
--------------
Given a :class:`~app.models.analytics.TimeSeries`, flag buckets that deviate
from the recent baseline, with a severity and an explanation.

Why start statistical
---------------------
A z-score over a rolling window needs no training data, no model artefact and
no retraining pipeline — it works on day one and its false positives are
explainable ("15x the trailing mean"), which is what makes an alert actionable.
Machine learning earns its place once there is labelled history; the
:class:`AnomalyDetector` interface is the seam where a model-based detector
drops in without touching any caller.

Detector characteristics
------------------------
==================  ========================================================
Detector            Strengths / weaknesses
==================  ========================================================
``zscore``          Simple, symmetric.  Assumes roughly normal data, and is
                    itself distorted by the outliers it looks for — a long
                    outage inflates the standard deviation and hides the next
                    one.  Best on counts.
``moving_average``  Compares each point to a *trailing* window, so it adapts
                    to trend and to daily seasonality.  Cannot see the very
                    first points (no history).
``iqr``             Robust: quartiles are unaffected by extreme values.  The
                    right choice for latency, which is heavily right-skewed.
``ewma``            Exponentially weighted: reacts fast to level shifts while
                    still smoothing noise.  One tunable (``alpha``).
==================  ========================================================

All detectors are **directional-aware**: for error rates and latency only
upward deviations matter, while for traffic a sudden *drop* is often the more
serious signal (an outage upstream), so both directions are reported with
distinct anomaly types.
"""

from __future__ import annotations

import math
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from app.analytics.statistics import iqr_bounds, moving_average, percentile, rolling_std
from app.core.registry import Registry
from app.models.analytics import Anomaly, TimeSeries
from app.models.enums import AnomalyType, Severity

#: Metric name → the anomaly type an upward deviation represents.
_UPWARD_TYPES: Final[dict[str, AnomalyType]] = {
    "errors": AnomalyType.ERROR_SPIKE,
    "error_rate": AnomalyType.ERROR_SPIKE,
    "server_errors": AnomalyType.SERVER_ERROR_SURGE,
    "client_errors": AnomalyType.UNUSUAL_PATTERN,
    "requests": AnomalyType.TRAFFIC_SPIKE,
    "latency_avg": AnomalyType.LATENCY_SPIKE,
    "latency_p95": AnomalyType.LATENCY_SPIKE,
    "latency_p99": AnomalyType.LATENCY_SPIKE,
    "latency_max": AnomalyType.LATENCY_SPIKE,
    "bytes": AnomalyType.TRAFFIC_SPIKE,
    "unique_ips": AnomalyType.UNUSUAL_PATTERN,
    "unique_users": AnomalyType.UNUSUAL_PATTERN,
}

#: Metrics where a downward deviation is also worth reporting.
_DROP_METRICS: Final[frozenset[str]] = frozenset({"requests", "bytes", "unique_users"})


def _anomaly_type(metric: str, direction: str) -> AnomalyType:
    if direction == "down":
        return AnomalyType.TRAFFIC_DROP if metric in _DROP_METRICS else AnomalyType.UNUSUAL_PATTERN
    return _UPWARD_TYPES.get(metric, AnomalyType.UNUSUAL_PATTERN)


def _severity_from_ratio(observed: float, expected: float, score: float) -> Severity:
    """Severity from both the *relative* size and the statistical strength.

    Using the ratio alone flags noise on near-zero baselines; using the score
    alone flags statistically clean but operationally trivial wobbles.  Both
    must be substantial for a high severity.
    """
    ratio = observed / expected if expected > 0 else (2.0 if observed > 0 else 1.0)
    if score >= 6 and ratio >= 5:
        return Severity.CRITICAL
    if score >= 4.5 and ratio >= 3:
        return Severity.HIGH
    if score >= 3 and ratio >= 1.75:
        return Severity.MEDIUM
    if score >= 2.5:
        return Severity.LOW
    return Severity.INFO


@dataclass(frozen=True, slots=True)
class DetectorConfig:
    """Shared tuning knobs."""

    threshold: float = 3.0
    window: int = 12
    min_history: int = 10
    iqr_multiplier: float = 1.5
    alpha: float = 0.3
    #: Ignore buckets whose value is below this — stops "1 error vs 0.1
    #: expected" from generating a page at 3 a.m.
    min_observed: float = 3.0


class AnomalyDetector(ABC):
    """Interface every detector implements."""

    name: str = "base"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()

    @abstractmethod
    def detect(self, series: TimeSeries, *, dimension: str | None = None) -> list[Anomaly]:
        """Return anomalies found in ``series``."""

    def _build(
        self,
        series: TimeSeries,
        index: int,
        observed: float,
        expected: float,
        score: float,
        direction: str,
        description: str,
        dimension: str | None,
    ) -> Anomaly:
        return Anomaly(
            type=_anomaly_type(series.metric, direction),
            detector=self.name,
            severity=_severity_from_ratio(observed, expected, abs(score)),
            bucket=series.points[index].bucket,
            metric=series.metric,
            observed=round(observed, 4),
            expected=round(expected, 4),
            deviation=round(observed - expected, 4),
            score=round(abs(score), 4),
            dimension=dimension,
            description=description,
        )


anomaly_registry: Registry[AnomalyDetector] = Registry("anomaly detector")


@anomaly_registry.register("zscore", "z")
class ZScoreDetector(AnomalyDetector):
    """Flags points more than ``threshold`` standard deviations from the mean."""

    name = "zscore"

    def detect(self, series: TimeSeries, *, dimension: str | None = None) -> list[Anomaly]:
        values = series.values
        if len(values) < self.config.min_history:
            return []
        mean = math.fsum(values) / len(values)
        variance = math.fsum((v - mean) ** 2 for v in values) / (len(values) - 1)
        stddev = math.sqrt(variance)
        if stddev == 0:
            return []

        anomalies: list[Anomaly] = []
        for index, value in enumerate(values):
            score = (value - mean) / stddev
            if abs(score) < self.config.threshold:
                continue
            direction = "up" if score > 0 else "down"
            if direction == "down" and series.metric not in _DROP_METRICS:
                continue
            if value < self.config.min_observed and direction == "up":
                continue
            anomalies.append(
                self._build(
                    series,
                    index,
                    value,
                    mean,
                    score,
                    direction,
                    f"{value:.2f} is {abs(score):.1f} standard deviations from the "
                    f"window mean of {mean:.2f}",
                    dimension,
                )
            )
        return anomalies


@anomaly_registry.register("moving_average", "ma", "rolling")
class MovingAverageDetector(AnomalyDetector):
    """Compares each point to its trailing moving average and rolling stddev.

    Adapts to trend and daily seasonality, which a global z-score cannot: a
    Monday-morning traffic ramp is normal, and only a deviation *from that ramp*
    is interesting.
    """

    name = "moving_average"

    def detect(self, series: TimeSeries, *, dimension: str | None = None) -> list[Anomaly]:
        values = series.values
        window = self.config.window
        if len(values) < max(self.config.min_history, window):
            return []
        averages = moving_average(values, window)
        deviations = rolling_std(values, window)

        anomalies: list[Anomaly] = []
        for index in range(window, len(values)):
            # Compare against the baseline *excluding* the current point, so a
            # spike cannot inflate the very baseline it is measured against.
            expected = averages[index - 1]
            spread = deviations[index - 1]
            observed = values[index]
            if spread <= 0:
                # A perfectly flat baseline has no scale to measure against, so
                # any change at all is the signal.  ``min_observed`` is a
                # noise guard for *upward* moves ("1 error vs 0.1 expected")
                # and must not suppress a drop to zero.
                if observed == expected:
                    continue
                if observed > expected and observed < self.config.min_observed:
                    continue
                score = self.config.threshold + 1
            else:
                score = (observed - expected) / spread
            if abs(score) < self.config.threshold:
                continue
            direction = "up" if observed > expected else "down"
            if direction == "down" and series.metric not in _DROP_METRICS:
                continue
            if direction == "up" and observed < self.config.min_observed:
                continue
            anomalies.append(
                self._build(
                    series,
                    index,
                    observed,
                    expected,
                    score,
                    direction,
                    f"{observed:.2f} deviates from the {window}-bucket trailing "
                    f"average of {expected:.2f}",
                    dimension,
                )
            )
        return anomalies


@anomaly_registry.register("iqr", "tukey")
class IqrDetector(AnomalyDetector):
    """Tukey fences — robust to the outliers it is looking for."""

    name = "iqr"

    def detect(self, series: TimeSeries, *, dimension: str | None = None) -> list[Anomaly]:
        values = series.values
        if len(values) < max(self.config.min_history, 8):
            return []
        lower, upper = iqr_bounds(values, self.config.iqr_multiplier)
        median = percentile(values, 0.5)
        spread = max(upper - median, 1e-9)

        anomalies: list[Anomaly] = []
        for index, value in enumerate(values):
            if lower <= value <= upper:
                continue
            direction = "up" if value > upper else "down"
            if direction == "down" and series.metric not in _DROP_METRICS:
                continue
            if direction == "up" and value < self.config.min_observed:
                continue
            score = abs(value - median) / spread * self.config.threshold
            anomalies.append(
                self._build(
                    series,
                    index,
                    value,
                    median,
                    score,
                    direction,
                    f"{value:.2f} falls outside the Tukey fence [{lower:.2f}, {upper:.2f}]",
                    dimension,
                )
            )
        return anomalies


@anomaly_registry.register("ewma", "exponential")
class EwmaDetector(AnomalyDetector):
    """Exponentially weighted moving average with an EW standard deviation.

    Reacts to level shifts faster than a fixed window while still smoothing
    noise; ``alpha`` trades responsiveness against stability.
    """

    name = "ewma"

    def detect(self, series: TimeSeries, *, dimension: str | None = None) -> list[Anomaly]:
        values = series.values
        if len(values) < self.config.min_history:
            return []
        alpha = self.config.alpha
        level = values[0]
        variance = 0.0
        anomalies: list[Anomaly] = []

        for index in range(1, len(values)):
            observed = values[index]
            deviation = observed - level
            spread = math.sqrt(variance)
            if spread > 0:
                score = deviation / spread
            elif deviation != 0:
                # Zero EW-variance means the series has been perfectly constant.
                # Any departure from it is, by construction, the first thing
                # that has ever happened — report it rather than dividing by
                # zero and silently never firing.
                score = math.copysign(self.config.threshold + 1, deviation)
            else:
                score = 0.0
            if abs(score) >= self.config.threshold and (
                observed >= self.config.min_observed or deviation < 0
            ):
                direction = "up" if deviation > 0 else "down"
                if direction == "up" or series.metric in _DROP_METRICS:
                    anomalies.append(
                        self._build(
                            series,
                            index,
                            observed,
                            level,
                            score,
                            direction,
                            f"{observed:.2f} deviates from the EWMA baseline of {level:.2f}",
                            dimension,
                        )
                    )
            # Update after scoring so the current point does not mask itself.
            variance = (1 - alpha) * (variance + alpha * deviation**2)
            level += alpha * deviation
        return anomalies


def build_detectors(
    names: Sequence[str] = ("moving_average", "iqr"),
    config: DetectorConfig | None = None,
) -> list[AnomalyDetector]:
    """Instantiate detectors by name."""
    return [anomaly_registry.resolve(name)(config) for name in names]


__all__ = [
    "AnomalyDetector",
    "DetectorConfig",
    "EwmaDetector",
    "IqrDetector",
    "MovingAverageDetector",
    "ZScoreDetector",
    "anomaly_registry",
    "build_detectors",
]
