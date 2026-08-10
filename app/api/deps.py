"""FastAPI dependencies.

Every expensive collaborator — the DuckDB engine, the analytics engine, the
cache, the job queue — is a **process-level singleton** created on first use
and reused for the lifetime of the app.  Building a DuckDB connection per
request would dominate response time; building one per worker process is the
right granularity.

Shared query parameters (time range, pagination) are declared once here so
every endpoint validates them identically, and their bounds come from
configuration rather than being scattered as literals across routers.
"""

import contextlib
import threading
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Annotated, Any, TypeVar, cast

from fastapi import Depends, Query

from app.analytics.engine import AnalyticsEngine
from app.analytics.security import SecurityAnalyzer
from app.anomaly_detection.service import AnomalyService
from app.cache import CacheBackend, build_cache
from app.core.config import Settings, get_settings
from app.core.timeutil import parse_range
from app.search.service import SearchService
from app.storage.duckdb_engine import DuckDBEngine
from app.workers.queue import JobQueue, get_queue

_lock = threading.Lock()
_singletons: dict[str, Any] = {}


S = TypeVar("S")


def _singleton(name: str, settings: Settings, factory: Callable[[], S]) -> S:
    """Cache a collaborator per (name, configuration).

    Keyed by the configuration, not just the name: a test that builds a second
    app against a different data root must not be served the first app's
    DuckDB engine — a bug that shows up as mysteriously empty results.
    """
    key = f"{name}@{settings.storage.data_root}#{settings.environment}"
    instance = _singletons.get(key)
    if instance is None:
        with _lock:
            instance = _singletons.get(key)
            if instance is None:
                instance = factory()
                _singletons[key] = instance
    return cast("S", instance)


def reset_dependencies() -> None:
    """Drop the singletons — used by tests and by ``/admin/reload``."""
    with _lock:
        for instance in _singletons.values():
            close = getattr(instance, "close", None)
            if callable(close):
                with contextlib.suppress(Exception):  # best-effort teardown
                    close()
        _singletons.clear()


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #
def get_engine(settings: Annotated[Settings, Depends(get_settings)]) -> DuckDBEngine:
    from app.storage import build_engine

    return _singleton("engine", settings, lambda: build_engine(settings))


def get_analytics(
    settings: Annotated[Settings, Depends(get_settings)],
    engine: Annotated[DuckDBEngine, Depends(get_engine)],
) -> AnalyticsEngine:
    return _singleton("analytics", settings, lambda: AnalyticsEngine(engine, settings))


def get_search(
    settings: Annotated[Settings, Depends(get_settings)],
    engine: Annotated[DuckDBEngine, Depends(get_engine)],
) -> SearchService:
    return _singleton("search", settings, lambda: SearchService(engine, settings))


def get_anomaly_service(
    settings: Annotated[Settings, Depends(get_settings)],
    analytics: Annotated[AnalyticsEngine, Depends(get_analytics)],
) -> AnomalyService:
    return _singleton("anomalies", settings, lambda: AnomalyService(analytics, settings))


def get_security_analyzer(
    settings: Annotated[Settings, Depends(get_settings)],
    engine: Annotated[DuckDBEngine, Depends(get_engine)],
) -> SecurityAnalyzer:
    return _singleton("security", settings, lambda: SecurityAnalyzer(engine, settings))


def get_cache(settings: Annotated[Settings, Depends(get_settings)]) -> CacheBackend:
    return _singleton("cache", settings, lambda: build_cache(settings.cache))


def get_job_queue(settings: Annotated[Settings, Depends(get_settings)]) -> JobQueue:
    return get_queue(settings)


# --------------------------------------------------------------------------- #
# Shared query parameters
# --------------------------------------------------------------------------- #
class TimeRangeParams:
    """``?start=&end=`` with sane defaults and a bounded span."""

    def __init__(
        self,
        start: Annotated[
            datetime | None,
            Query(description="Inclusive start of the window (ISO-8601, UTC)."),
        ] = None,
        end: Annotated[datetime | None, Query(description="Inclusive end of the window.")] = None,
        hours: Annotated[
            float | None,
            Query(
                ge=0.01, le=8_760, description="Window length ending now, if start/end are absent."
            ),
        ] = None,
    ) -> None:
        from datetime import timedelta

        span = timedelta(hours=hours) if hours else timedelta(days=1)
        self.start, self.end = parse_range(start, end, default_span=span)

    def as_tuple(self) -> tuple[datetime, datetime]:
        return self.start, self.end


class PaginationParams:
    """``?page=&page_size=`` clamped to the configured maximum."""

    def __init__(
        self,
        page: Annotated[int, Query(ge=1, le=100_000)] = 1,
        page_size: Annotated[int, Query(ge=1, le=10_000)] = 50,
        settings: Annotated[Settings, Depends(get_settings)] = None,  # type: ignore[assignment]
    ) -> None:
        config = settings or get_settings()
        self.page = page
        self.page_size = min(page_size, config.api.max_page_size)

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size


class FilterParams:
    """Common log filters, shared by search and analytics endpoints."""

    def __init__(
        self,
        service: Annotated[str | None, Query(max_length=255)] = None,
        level: Annotated[str | None, Query(max_length=32)] = None,
        hostname: Annotated[str | None, Query(max_length=255)] = None,
        environment: Annotated[str | None, Query(max_length=32)] = None,
        status_code: Annotated[int | None, Query(ge=100, le=599)] = None,
        endpoint: Annotated[str | None, Query(max_length=2_048)] = None,
        ip_address: Annotated[str | None, Query(max_length=64)] = None,
    ) -> None:
        self.values: dict[str, Any] = {
            "service": service,
            "level": level.upper() if level else None,
            "hostname": hostname,
            "environment": environment,
            "status_code": status_code,
            "endpoint": endpoint,
            "ip_address": ip_address,
        }

    def active(self) -> dict[str, Any]:
        return {key: value for key, value in self.values.items() if value is not None}

    def cache_fragment(self) -> str:
        return "|".join(f"{k}={v}" for k, v in sorted(self.active().items()))


def cacheable(settings: Settings, prefix: str) -> bool:
    """Whether a view may be cached at all (see ``cache.cacheable_prefixes``)."""
    return any(prefix.startswith(allowed) for allowed in settings.cache.cacheable_prefixes)


def cache_key(
    cache: CacheBackend,
    prefix: str,
    time_range: TimeRangeParams,
    filters: Mapping[str, Any] | None = None,
    **extra: Any,
) -> str:
    """Deterministic cache key for an analytics view."""
    parts = [
        time_range.start.isoformat(),
        time_range.end.isoformat(),
        *(f"{k}={v}" for k, v in sorted((filters or {}).items())),
        *(f"{k}={v}" for k, v in sorted(extra.items())),
    ]
    return cache.build_key(prefix, *parts)


__all__ = [
    "FilterParams",
    "PaginationParams",
    "TimeRangeParams",
    "cache_key",
    "cacheable",
    "get_analytics",
    "get_anomaly_service",
    "get_cache",
    "get_engine",
    "get_job_queue",
    "get_search",
    "get_security_analyzer",
    "reset_dependencies",
]
