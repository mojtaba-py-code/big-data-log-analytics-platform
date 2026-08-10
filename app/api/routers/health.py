"""Health, readiness and metrics endpoints.

Three distinct questions, three endpoints — conflating them is what makes
Kubernetes restart a perfectly healthy pod during a Redis blip:

``/health/live``   Is the process alive?  Never touches a dependency.
``/health/ready``  Can it serve traffic?  Checks storage and cache; degrades
                   rather than failing when only the cache is down, because
                   the cache is not load-bearing.
``/health``        Human-facing summary with component detail.

These endpoints are unauthenticated (a probe has no credentials) and therefore
expose **no** configuration, paths or versions of dependencies.
"""

import time
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Response, status

from app import __version__
from app.api.deps import get_analytics, get_cache, get_engine
from app.cache import CacheBackend
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.metrics import global_metrics, memory_usage_mb
from app.core.timeutil import to_iso, utcnow
from app.storage.duckdb_engine import DuckDBEngine

log = get_logger(__name__)

router = APIRouter(tags=["health"])

_STARTED_AT = time.monotonic()


@router.get("/health/live", summary="Liveness probe")
async def live() -> dict[str, Any]:
    """Alive if this returns at all."""
    return {"status": "alive", "uptime_seconds": round(time.monotonic() - _STARTED_AT, 1)}


@router.get("/health/ready", summary="Readiness probe")
async def ready(
    response: Response,
    engine: Annotated[DuckDBEngine, Depends(get_engine)],
    cache: Annotated[CacheBackend, Depends(get_cache)],
) -> dict[str, Any]:
    """Ready when the analytical store is reachable."""
    checks: dict[str, str] = {}
    ok = True
    try:
        engine.has_data()
        checks["storage"] = "ok"
    except Exception:  # noqa: BLE001 - the point is to report, not to raise
        checks["storage"] = "unavailable"
        ok = False
    checks["cache"] = "ok" if cache.health().get("healthy") else "degraded"

    if not ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ready" if ok else "not_ready", "checks": checks}


@router.get("/health", summary="Service health summary")
async def health(
    settings: Annotated[Settings, Depends(get_settings)],
    engine: Annotated[DuckDBEngine, Depends(get_engine)],
    cache: Annotated[CacheBackend, Depends(get_cache)],
) -> dict[str, Any]:
    """Aggregate health with component detail."""
    components: dict[str, Any] = {}
    try:
        summary = engine.dataset_summary()
        components["storage"] = {
            "status": "ok",
            "records": summary.get("records", 0),
            "first_event": to_iso(summary["first_event"]) if summary.get("first_event") else None,
            "last_event": to_iso(summary["last_event"]) if summary.get("last_event") else None,
        }
    except Exception:  # noqa: BLE001
        components["storage"] = {"status": "unavailable"}

    cache_health = cache.health()
    components["cache"] = {
        "status": "ok" if cache_health.get("healthy") else "degraded",
        "backend": cache_health.get("backend"),
        "hit_rate": cache_health.get("hit_rate"),
    }

    healthy = components["storage"]["status"] == "ok"
    return {
        "status": "healthy" if healthy else "degraded",
        "version": __version__,
        "environment": settings.environment,
        "uptime_seconds": round(time.monotonic() - _STARTED_AT, 1),
        "timestamp": to_iso(utcnow()),
        "components": components,
    }


@router.get("/metrics", summary="Prometheus metrics", response_class=Response)
async def metrics(
    cache: Annotated[CacheBackend, Depends(get_cache)],
) -> Response:
    """Process metrics in Prometheus text format."""
    global_metrics.set_gauge("process_memory_mb", memory_usage_mb())
    global_metrics.set_gauge("uptime_seconds", time.monotonic() - _STARTED_AT)
    stats = cache.health()
    global_metrics.set_gauge("cache_hit_rate", float(stats.get("hit_rate", 0.0)))
    global_metrics.set_gauge("cache_hits", float(stats.get("hits", 0)))
    global_metrics.set_gauge("cache_misses", float(stats.get("misses", 0)))
    return Response(
        content=global_metrics.to_prometheus(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get("/stats", summary="Dataset statistics")
async def stats(
    analytics: Annotated[Any, Depends(get_analytics)],
    engine: Annotated[DuckDBEngine, Depends(get_engine)],
) -> dict[str, Any]:
    """Size and shape of the stored dataset."""
    summary = engine.dataset_summary()
    return {
        "records": summary.get("records", 0),
        "services": summary.get("services", 0),
        "first_event": to_iso(summary["first_event"]) if summary.get("first_event") else None,
        "last_event": to_iso(summary["last_event"]) if summary.get("last_event") else None,
        "levels": analytics.distinct_values("level", limit=20),
    }


__all__ = ["router"]
