"""Anomaly detection layer."""

from __future__ import annotations

from app.anomaly_detection.detectors import (
    AnomalyDetector,
    DetectorConfig,
    EwmaDetector,
    IqrDetector,
    MovingAverageDetector,
    ZScoreDetector,
    anomaly_registry,
    build_detectors,
)
from app.anomaly_detection.service import DEFAULT_METRICS, AnomalyService, deduplicate

__all__ = [
    "DEFAULT_METRICS",
    "AnomalyDetector",
    "AnomalyService",
    "DetectorConfig",
    "EwmaDetector",
    "IqrDetector",
    "MovingAverageDetector",
    "ZScoreDetector",
    "anomaly_registry",
    "build_detectors",
    "deduplicate",
]
