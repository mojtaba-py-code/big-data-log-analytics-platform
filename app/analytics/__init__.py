"""Analytics layer: aggregation, statistics, security analysis, reporting."""

from __future__ import annotations

from app.analytics.engine import AVAILABLE_METRICS, AnalyticsEngine
from app.analytics.reports import (
    ReportBuilder,
    render_html,
    render_json,
    render_markdown,
    save_report,
)
from app.analytics.security import SecurityAnalyzer, score_finding
from app.analytics.statistics import (
    build_series,
    describe,
    iqr_bounds,
    moving_average,
    percentile,
    rolling_std,
    top_n,
    zscores,
)

__all__ = [
    "AVAILABLE_METRICS",
    "AnalyticsEngine",
    "ReportBuilder",
    "SecurityAnalyzer",
    "build_series",
    "describe",
    "iqr_bounds",
    "moving_average",
    "percentile",
    "render_html",
    "render_json",
    "render_markdown",
    "rolling_std",
    "save_report",
    "score_finding",
    "top_n",
    "zscores",
]
