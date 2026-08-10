"""Report endpoints.

``GET /reports/daily``    yesterday (or a named day) in full
``GET /reports/summary``  a rolling window ending now
``GET /reports/{name}``   a previously generated, stored report

Reports are expensive — several aggregations plus anomaly and security scans —
so they are cached longer than the individual analytics views and can also be
generated asynchronously via ``POST /jobs/report``.
"""

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Response, status

from app.analytics.engine import AnalyticsEngine
from app.analytics.reports import ReportBuilder, render_html, render_markdown
from app.analytics.security import SecurityAnalyzer
from app.anomaly_detection.service import AnomalyService
from app.api.deps import (
    TimeRangeParams,
    get_analytics,
    get_anomaly_service,
    get_cache,
    get_security_analyzer,
)
from app.api.security import RequireRead
from app.cache import CacheBackend
from app.core.config import Settings, get_settings
from app.core.paths import safe_filename
from app.models.analytics import Report

router = APIRouter(prefix="/reports", tags=["reports"], dependencies=[RequireRead])


def _builder(
    settings: Settings,
    analytics: AnalyticsEngine,
    anomalies: AnomalyService,
    security: SecurityAnalyzer,
) -> ReportBuilder:
    return ReportBuilder(settings, analytics, anomalies, security)


def _respond(report: Report, fmt: str) -> Any:
    if fmt == "markdown":
        return Response(content=render_markdown(report), media_type="text/markdown")
    if fmt == "html":
        return Response(content=render_html(report), media_type="text/html")
    return report.model_dump(mode="json")


@router.get("/daily", summary="Daily report")
async def daily(
    settings: Annotated[Settings, Depends(get_settings)],
    analytics: Annotated[AnalyticsEngine, Depends(get_analytics)],
    anomalies: Annotated[AnomalyService, Depends(get_anomaly_service)],
    security: Annotated[SecurityAnalyzer, Depends(get_security_analyzer)],
    cache: Annotated[CacheBackend, Depends(get_cache)],
    date: Annotated[datetime | None, Query(description="Day to report on (UTC).")] = None,
    fmt: Annotated[str, Query(pattern="^(json|markdown|html)$", alias="format")] = "json",
) -> Any:
    """A full report for one calendar day."""
    key = cache.build_key("reports.daily", date.date().isoformat() if date else "yesterday")
    cached = cache.get(key)
    if cached is not None and fmt == "json":
        return cached
    report = _builder(settings, analytics, anomalies, security).daily(date)
    cache.set(key, report.model_dump(mode="json"), settings.cache.default_ttl_seconds * 4)
    return _respond(report, fmt)


@router.get("/summary", summary="Rolling summary report")
async def summary(
    settings: Annotated[Settings, Depends(get_settings)],
    analytics: Annotated[AnalyticsEngine, Depends(get_analytics)],
    anomalies: Annotated[AnomalyService, Depends(get_anomaly_service)],
    security: Annotated[SecurityAnalyzer, Depends(get_security_analyzer)],
    cache: Annotated[CacheBackend, Depends(get_cache)],
    time_range: Annotated[TimeRangeParams, Depends()],
    fmt: Annotated[str, Query(pattern="^(json|markdown|html)$", alias="format")] = "json",
) -> Any:
    """A report over an arbitrary window."""
    key = cache.build_key(
        "reports.summary", time_range.start.isoformat(), time_range.end.isoformat()
    )
    cached = cache.get(key)
    if cached is not None and fmt == "json":
        return cached
    report = _builder(settings, analytics, anomalies, security).build(
        time_range.start, time_range.end
    )
    cache.set(key, report.model_dump(mode="json"), settings.cache.default_ttl_seconds)
    return _respond(report, fmt)


@router.get("/stored", summary="List stored reports")
async def stored(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, Any]:
    """Reports previously written to disk by the report job."""
    directory = settings.storage.data_root / "reports"
    if not directory.is_dir():
        return {"reports": []}
    entries: list[dict[str, Any]] = [
        {
            "name": path.name,
            "size_bytes": path.stat().st_size,
            "modified": path.stat().st_mtime,
        }
        for path in directory.iterdir()
        if path.is_file()
    ]
    entries.sort(key=lambda item: float(item["modified"]), reverse=True)
    return {"reports": entries[:100]}


@router.get("/stored/{name}", summary="Fetch a stored report")
async def fetch_stored(
    settings: Annotated[Settings, Depends(get_settings)],
    name: Annotated[str, Path(max_length=180)],
) -> Any:
    """Read one stored report.

    The name is sanitised and re-resolved under the reports directory, so a
    traversal attempt (``../../etc/passwd``) cannot escape it.
    """
    from app.core.exceptions import PathTraversalError
    from app.core.paths import resolve_within

    directory = settings.storage.data_root / "reports"
    try:
        path = resolve_within(directory / safe_filename(name), [directory], must_exist=True)
    except (PathTraversalError, FileNotFoundError) as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="report not found"
        ) from exc

    media = {
        ".json": "application/json",
        ".md": "text/markdown",
        ".html": "text/html",
    }.get(path.suffix.lower(), "text/plain")
    return Response(content=path.read_text(encoding="utf-8"), media_type=media)


__all__ = ["router"]
