"""Analytics endpoints.

Every view here is read-only, cacheable and derived from the same
:class:`~app.analytics.engine.AnalyticsEngine`, so the API and the CLI can
never disagree about what "error rate" means.

Caching
-------
Responses are cached under a key derived from the *view name plus every
parameter that changes the answer*.  Only prefixes listed in
``cache.cacheable_prefixes`` are cached at all, and nothing user-specific is —
these endpoints return aggregates over shared data, never per-caller results.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from app.analytics.engine import AVAILABLE_METRICS, AnalyticsEngine
from app.analytics.security import SecurityAnalyzer
from app.anomaly_detection.service import DEFAULT_METRICS, AnomalyService
from app.api.deps import (
    FilterParams,
    TimeRangeParams,
    cache_key,
    cacheable,
    get_analytics,
    get_anomaly_service,
    get_cache,
    get_security_analyzer,
)
from app.api.security import RequireRead
from app.cache import CacheBackend
from app.core.config import Settings, get_settings
from app.core.timeutil import WINDOWS
from app.models.enums import Severity

router = APIRouter(prefix="/analytics", tags=["analytics"], dependencies=[RequireRead])

_WINDOW_PATTERN = "^(1m|5m|15m|1h|6h|1d)$"


def _cached_view(
    cache: CacheBackend,
    settings: Settings,
    prefix: str,
    time_range: TimeRangeParams,
    filters: dict[str, Any],
    factory: Any,
    **extra: Any,
) -> Any:
    """Serve a view from cache when the prefix is permitted to be cached."""
    if not cacheable(settings, prefix):
        return factory()
    key = cache_key(cache, prefix, time_range, filters, **extra)
    hit = cache.get(key)
    if hit is not None:
        return hit
    value = factory()
    payload = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
    cache.set(key, payload, settings.cache.default_ttl_seconds)
    return payload


@router.get("/overview", summary="Headline metrics")
async def overview(
    time_range: Annotated[TimeRangeParams, Depends()],
    filters: Annotated[FilterParams, Depends()],
    analytics: Annotated[AnalyticsEngine, Depends(get_analytics)],
    cache: Annotated[CacheBackend, Depends(get_cache)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Any:
    """Totals, error rate, latency percentiles and active services."""
    return _cached_view(
        cache,
        settings,
        "analytics.overview",
        time_range,
        filters.active(),
        lambda: analytics.overview(time_range.start, time_range.end, filters.active()),
    )


@router.get("/errors", summary="Error analysis")
async def errors(
    time_range: Annotated[TimeRangeParams, Depends()],
    filters: Annotated[FilterParams, Depends()],
    analytics: Annotated[AnalyticsEngine, Depends(get_analytics)],
    cache: Annotated[CacheBackend, Depends(get_cache)],
    settings: Annotated[Settings, Depends(get_settings)],
    window: Annotated[str, Query(pattern=_WINDOW_PATTERN)] = "5m",
    top: Annotated[int, Query(ge=1, le=100)] = 10,
) -> Any:
    """Error totals and breakdowns by service, endpoint, host and level."""
    return _cached_view(
        cache,
        settings,
        "analytics.errors",
        time_range,
        filters.active(),
        lambda: analytics.errors(
            time_range.start, time_range.end, filters.active(), window=window, top=top
        ),
        window=window,
        top=top,
    )


@router.get("/traffic", summary="Traffic analysis")
async def traffic(
    time_range: Annotated[TimeRangeParams, Depends()],
    filters: Annotated[FilterParams, Depends()],
    analytics: Annotated[AnalyticsEngine, Depends(get_analytics)],
    cache: Annotated[CacheBackend, Depends(get_cache)],
    settings: Annotated[Settings, Depends(get_settings)],
    window: Annotated[str, Query(pattern=_WINDOW_PATTERN)] = "5m",
    top: Annotated[int, Query(ge=1, le=100)] = 10,
) -> Any:
    """Request rates plus top IPs, endpoints, user agents and methods."""
    return _cached_view(
        cache,
        settings,
        "analytics.traffic",
        time_range,
        filters.active(),
        lambda: analytics.traffic(
            time_range.start, time_range.end, filters.active(), window=window, top=top
        ),
        window=window,
        top=top,
    )


@router.get("/latency", summary="Latency analysis")
async def latency(
    time_range: Annotated[TimeRangeParams, Depends()],
    filters: Annotated[FilterParams, Depends()],
    analytics: Annotated[AnalyticsEngine, Depends(get_analytics)],
    cache: Annotated[CacheBackend, Depends(get_cache)],
    settings: Annotated[Settings, Depends(get_settings)],
    window: Annotated[str, Query(pattern=_WINDOW_PATTERN)] = "5m",
    top: Annotated[int, Query(ge=1, le=100)] = 10,
) -> Any:
    """Overall and per-dimension latency statistics (P50/P95/P99)."""
    return _cached_view(
        cache,
        settings,
        "analytics.latency",
        time_range,
        filters.active(),
        lambda: analytics.latency(
            time_range.start, time_range.end, filters.active(), window=window, top=top
        ),
        window=window,
        top=top,
    )


@router.get("/status-codes", summary="HTTP status distribution")
async def status_codes(
    time_range: Annotated[TimeRangeParams, Depends()],
    filters: Annotated[FilterParams, Depends()],
    analytics: Annotated[AnalyticsEngine, Depends(get_analytics)],
    cache: Annotated[CacheBackend, Depends(get_cache)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Any:
    """2xx/3xx/4xx/5xx split and the most frequent individual codes."""
    return _cached_view(
        cache,
        settings,
        "analytics.status_codes",
        time_range,
        filters.active(),
        lambda: analytics.status_codes(time_range.start, time_range.end, filters.active()),
    )


@router.get("/services", summary="Per-service health")
async def services(
    time_range: Annotated[TimeRangeParams, Depends()],
    filters: Annotated[FilterParams, Depends()],
    analytics: Annotated[AnalyticsEngine, Depends(get_analytics)],
    cache: Annotated[CacheBackend, Depends(get_cache)],
    settings: Annotated[Settings, Depends(get_settings)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Any:
    """Throughput, failure rate, availability and latency per service."""
    return _cached_view(
        cache,
        settings,
        "analytics.services",
        time_range,
        filters.active(),
        lambda: analytics.services(time_range.start, time_range.end, filters.active(), limit=limit),
        limit=limit,
    )


@router.get("/timeseries", summary="Bucketed time series")
async def timeseries(
    time_range: Annotated[TimeRangeParams, Depends()],
    filters: Annotated[FilterParams, Depends()],
    analytics: Annotated[AnalyticsEngine, Depends(get_analytics)],
    cache: Annotated[CacheBackend, Depends(get_cache)],
    settings: Annotated[Settings, Depends(get_settings)],
    metric: Annotated[
        str, Query(description=f"One of: {', '.join(AVAILABLE_METRICS)}")
    ] = "requests",
    window: Annotated[str, Query(pattern=_WINDOW_PATTERN)] = "5m",
) -> Any:
    """One metric over time, gap-filled."""
    if metric not in AVAILABLE_METRICS:
        from fastapi import HTTPException
        from fastapi import status as http_status

        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail=f"unknown metric; choose from: {', '.join(AVAILABLE_METRICS)}",
        )
    return _cached_view(
        cache,
        settings,
        "analytics.timeseries",
        time_range,
        filters.active(),
        lambda: analytics.timeseries(
            metric, time_range.start, time_range.end, filters.active(), window=window
        ),
        metric=metric,
        window=window,
    )


@router.get("/anomalies", summary="Detected anomalies")
async def anomalies(
    time_range: Annotated[TimeRangeParams, Depends()],
    filters: Annotated[FilterParams, Depends()],
    service: Annotated[AnomalyService, Depends(get_anomaly_service)],
    cache: Annotated[CacheBackend, Depends(get_cache)],
    settings: Annotated[Settings, Depends(get_settings)],
    window: Annotated[str, Query(pattern=_WINDOW_PATTERN)] = "5m",
    metrics: Annotated[list[str] | None, Query()] = None,
    min_severity: Annotated[Severity, Query()] = Severity.LOW,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> Any:
    """Statistically unusual buckets across the selected metrics."""
    chosen = tuple(m for m in (metrics or DEFAULT_METRICS) if m in AVAILABLE_METRICS)

    def compute() -> dict[str, Any]:
        found = service.scan(
            time_range.start,
            time_range.end,
            metrics=chosen or DEFAULT_METRICS,
            window=window,
            filters=filters.active(),
            min_severity=min_severity,
            limit=limit,
        )
        return {
            "window": window,
            "metrics": list(chosen or DEFAULT_METRICS),
            "count": len(found),
            "anomalies": [a.model_dump(mode="json") for a in found],
        }

    return _cached_view(
        cache,
        settings,
        "analytics.anomalies",
        time_range,
        filters.active(),
        compute,
        window=window,
        metrics=",".join(chosen),
        min_severity=str(min_severity),
        limit=limit,
    )


@router.get("/security", summary="Security findings")
async def security(
    time_range: Annotated[TimeRangeParams, Depends()],
    analyzer: Annotated[SecurityAnalyzer, Depends(get_security_analyzer)],
    cache: Annotated[CacheBackend, Depends(get_cache)],
    settings: Annotated[Settings, Depends(get_settings)],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> Any:
    """Suspicious behaviour with risk scores and supporting evidence."""

    def compute() -> dict[str, Any]:
        findings = analyzer.analyze(time_range.start, time_range.end, limit=limit)
        return {
            "count": len(findings),
            "findings": [f.model_dump(mode="json") for f in findings],
        }

    return _cached_view(cache, settings, "analytics.security", time_range, {}, compute, limit=limit)


@router.get("/windows", summary="Supported aggregation windows")
async def windows() -> dict[str, Any]:
    return {
        "windows": sorted(WINDOWS, key=lambda w: WINDOWS[w]),
        "metrics": list(AVAILABLE_METRICS),
    }


__all__ = ["router"]
