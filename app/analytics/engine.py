"""Analytics engine.

Responsibility
--------------
Answer the operational questions — error rates, status distributions, latency
percentiles, traffic shape, per-service health — over an arbitrary time window,
at any dataset size.

Why the aggregation happens in SQL
----------------------------------
Pulling rows into Python and aggregating them there costs one Python object per
row: at 10 M records that is minutes of interpreter time and gigabytes of RAM.
DuckDB does the same work vectorised, over columnar data, using only the
columns each query touches, and spills to disk if the group-by outgrows memory.
The engine's job is therefore to *compose safe SQL* and shape the result, not
to compute.

Safety
------
Every user-supplied value is a bound parameter.  Every user-supplied *column*
goes through :func:`app.storage.duckdb_engine.validate_column`, an allow-list.
The dataset path comes from the platform's own partition layout.  There is no
code path in which request text reaches the SQL string.

Caching
-------
The engine is deliberately cache-free; caching is a decision for the caller
(the API wraps it with :mod:`app.cache`), because a CLI run and an HTTP request
have very different staleness tolerances.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.timeutil import WINDOW_SQL, ensure_utc, parse_range, utcnow
from app.models.analytics import (
    CountItem,
    ErrorAnalytics,
    LatencyAnalytics,
    OverviewMetrics,
    ServiceAnalytics,
    ServiceHealth,
    Stats,
    StatusCodeAnalytics,
    TimeRange,
    TimeSeries,
    TimeSeriesPoint,
    TrafficAnalytics,
)
from app.storage.duckdb_engine import DuckDBEngine, validate_column

log = get_logger(__name__)

#: Severity levels that count as an error.  Kept in one place so the API, the
#: dashboard and the reports cannot disagree about what "error rate" means.
ERROR_LEVELS: Final[tuple[str, ...]] = ("ERROR", "CRITICAL", "ALERT", "EMERGENCY")

_ERROR_PREDICATE: Final[str] = (
    "(level IN ('ERROR', 'CRITICAL', 'ALERT', 'EMERGENCY') OR status_code >= 500)"
)

#: Health thresholds for :class:`ServiceHealth`.
DEGRADED_FAILURE_RATE: Final[float] = 0.02
UNHEALTHY_FAILURE_RATE: Final[float] = 0.10


class AnalyticsEngine:
    """Computes every analytics view from the processed Parquet dataset."""

    def __init__(
        self,
        engine: DuckDBEngine | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        if engine is None:
            from app.storage import build_engine

            engine = build_engine(self.settings)
        self.engine = engine

    # -- helpers ------------------------------------------------------------- #
    def _scope(
        self,
        start: datetime | None,
        end: datetime | None,
        filters: Mapping[str, Any] | None = None,
    ) -> tuple[str, str, list[Any], TimeRange] | None:
        """Build ``(source, where, params, range)`` or ``None`` when no data.

        ``params`` opens with the scan's own bound values (the pruned file
        list), because the scan appears in ``FROM`` before any predicate.
        Every caller therefore spreads ``params`` first and appends its own
        values after it.
        """
        start_dt, end_dt = parse_range(start, end)
        scan = self.engine.scan(start_dt, end_dt)
        if scan is None:
            return None
        source, scan_params = scan
        clauses = ["timestamp >= ?", "timestamp <= ?"]
        params: list[Any] = [*scan_params, start_dt, end_dt]
        for column, value in (filters or {}).items():
            if value is None:
                continue
            validated = validate_column(column)
            if isinstance(value, (list, tuple, set)):
                items = list(value)
                if not items:
                    continue
                placeholders = ", ".join("?" for _ in items)
                clauses.append(f"{validated} IN ({placeholders})")
                params.extend(items)
            else:
                clauses.append(f"{validated} = ?")
                params.append(value)
        return source, " AND ".join(clauses), params, TimeRange(start=start_dt, end=end_dt)

    def _counts(
        self,
        column: str,
        source: str,
        where: str,
        params: Sequence[Any],
        *,
        extra: str = "",
        limit: int = 10,
    ) -> list[CountItem]:
        """Top-N distinct values of ``column`` under a predicate."""
        validated = validate_column(column)
        predicate = f"{where} AND {extra}" if extra else where
        sql = (
            f"SELECT {validated} AS key, COUNT(*) AS total "  # noqa: S608 - allow-listed
            f"FROM {source} WHERE {predicate} AND {validated} IS NOT NULL "
            f"GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT ?"
        )
        rows = self.engine.execute(sql, [*params, limit])
        total = sum(int(row["total"]) for row in rows)
        return [
            CountItem(
                key=str(row["key"]),
                count=int(row["total"]),
                percentage=round(int(row["total"]) / total * 100, 4) if total else 0.0,
            )
            for row in rows
        ]

    # -- views --------------------------------------------------------------- #
    def overview(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        filters: Mapping[str, Any] | None = None,
    ) -> OverviewMetrics:
        """Headline metrics — one query, all tiles."""
        scope = self._scope(start, end, filters)
        if scope is None:
            now = utcnow()
            return OverviewMetrics(time_range=TimeRange(start=start or now, end=end or now))
        source, where, params, time_range = scope

        sql = f"""
            SELECT
                COUNT(*)                                            AS total_records,
                COUNT(status_code)                                  AS total_requests,
                COUNT(*) FILTER (WHERE {_ERROR_PREDICATE})          AS total_errors,
                AVG(response_time_ms)                               AS avg_latency,
                approx_quantile(response_time_ms, 0.95)             AS p95_latency,
                approx_quantile(response_time_ms, 0.99)             AS p99_latency,
                COUNT(DISTINCT service)                             AS active_services
            FROM {source} WHERE {where}
        """  # noqa: S608 - source and predicate are validated, values are bound
        rows = self.engine.execute(sql, params, limit=1)
        row = rows[0] if rows else {}
        records = int(row.get("total_records") or 0)
        errors = int(row.get("total_errors") or 0)
        return OverviewMetrics(
            time_range=time_range,
            total_records=records,
            total_requests=int(row.get("total_requests") or 0),
            total_errors=errors,
            error_rate=round(errors / records, 6) if records else 0.0,
            average_latency_ms=round(float(row.get("avg_latency") or 0.0), 3),
            p95_latency_ms=round(float(row.get("p95_latency") or 0.0), 3),
            p99_latency_ms=round(float(row.get("p99_latency") or 0.0), 3),
            active_services=int(row.get("active_services") or 0),
        )

    def errors(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        filters: Mapping[str, Any] | None = None,
        *,
        window: str | None = None,
        top: int = 10,
    ) -> ErrorAnalytics:
        scope = self._scope(start, end, filters)
        if scope is None:
            now = utcnow()
            return ErrorAnalytics(time_range=TimeRange(start=start or now, end=end or now))
        source, where, params, time_range = scope

        totals = self.engine.execute(
            f"SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE {_ERROR_PREDICATE}) AS errors "  # noqa: S608 - identifiers are allow-listed, values are bound (see module docstring)
            f"FROM {source} WHERE {where}",  # noqa: S608 - see module docstring
            params,
            limit=1,
        )
        total = int(totals[0]["total"]) if totals else 0
        error_count = int(totals[0]["errors"]) if totals else 0

        return ErrorAnalytics(
            time_range=time_range,
            total_records=total,
            total_errors=error_count,
            error_rate=round(error_count / total, 6) if total else 0.0,
            by_service=self._counts(
                "service", source, where, params, extra=_ERROR_PREDICATE, limit=top
            ),
            by_endpoint=self._counts(
                "endpoint", source, where, params, extra=_ERROR_PREDICATE, limit=top
            ),
            by_host=self._counts(
                "hostname", source, where, params, extra=_ERROR_PREDICATE, limit=top
            ),
            by_level=self._counts(
                "level", source, where, params, extra=_ERROR_PREDICATE, limit=top
            ),
            over_time=self.timeseries(
                "errors",
                start,
                end,
                filters,
                window=window or self.settings.analytics.default_window,
            ),
        )

    def status_codes(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        filters: Mapping[str, Any] | None = None,
    ) -> StatusCodeAnalytics:
        scope = self._scope(start, end, filters)
        if scope is None:
            now = utcnow()
            return StatusCodeAnalytics(time_range=TimeRange(start=start or now, end=end or now))
        source, where, params, time_range = scope

        rows = self.engine.execute(
            "SELECT CAST(status_code / 100 AS INTEGER) AS class, COUNT(*) AS total "  # noqa: S608 - identifiers are allow-listed, values are bound (see module docstring)
            f"FROM {source} WHERE {where} AND status_code IS NOT NULL "  # noqa: S608
            "GROUP BY 1 ORDER BY 1",
            params,
        )
        by_class = {f"{int(row['class'])}xx": int(row["total"]) for row in rows}
        total = sum(by_class.values())
        return StatusCodeAnalytics(
            time_range=time_range,
            total_requests=total,
            by_class=by_class,
            by_code=self._counts("status_code", source, where, params, limit=15),
            success_rate=round((by_class.get("2xx", 0) + by_class.get("3xx", 0)) / total, 6)
            if total
            else 0.0,
            client_error_rate=round(by_class.get("4xx", 0) / total, 6) if total else 0.0,
            server_error_rate=round(by_class.get("5xx", 0) / total, 6) if total else 0.0,
        )

    def latency(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        filters: Mapping[str, Any] | None = None,
        *,
        top: int = 10,
        window: str | None = None,
    ) -> LatencyAnalytics:
        scope = self._scope(start, end, filters)
        if scope is None:
            now = utcnow()
            return LatencyAnalytics(time_range=TimeRange(start=start or now, end=end or now))
        source, where, params, time_range = scope
        latency_where = f"{where} AND response_time_ms IS NOT NULL"

        overall_rows = self.engine.execute(
            f"SELECT {_STATS_SELECT} FROM {source} WHERE {latency_where}",  # noqa: S608
            params,
            limit=1,
        )
        by_service = self._grouped_stats("service", source, latency_where, params, top)
        by_endpoint = self._grouped_stats("endpoint", source, latency_where, params, top)

        return LatencyAnalytics(
            time_range=time_range,
            overall=_row_to_stats(overall_rows[0] if overall_rows else {}),
            by_service=by_service,
            by_endpoint=by_endpoint,
            over_time=self.timeseries(
                "latency_p95",
                start,
                end,
                filters,
                window=window or self.settings.analytics.default_window,
            ),
        )

    def _grouped_stats(
        self, column: str, source: str, where: str, params: Sequence[Any], limit: int
    ) -> dict[str, Stats]:
        validated = validate_column(column)
        sql = (
            f"SELECT {validated} AS key, {_STATS_SELECT} "  # noqa: S608 - allow-listed
            f"FROM {source} WHERE {where} AND {validated} IS NOT NULL "
            f"GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT ?"
        )
        return {
            str(row["key"]): _row_to_stats(row)
            for row in self.engine.execute(sql, [*params, limit])
        }

    def traffic(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        filters: Mapping[str, Any] | None = None,
        *,
        top: int = 10,
        window: str | None = None,
    ) -> TrafficAnalytics:
        scope = self._scope(start, end, filters)
        if scope is None:
            now = utcnow()
            return TrafficAnalytics(time_range=TimeRange(start=start or now, end=end or now))
        source, where, params, time_range = scope

        rows = self.engine.execute(
            "SELECT COUNT(*) AS total, COALESCE(SUM(bytes_sent), 0) AS bytes "  # noqa: S608 - identifiers are allow-listed, values are bound (see module docstring)
            f"FROM {source} WHERE {where}",  # noqa: S608
            params,
            limit=1,
        )
        total = int(rows[0]["total"]) if rows else 0
        seconds = max(time_range.seconds, 1.0)

        return TrafficAnalytics(
            time_range=time_range,
            total_requests=total,
            requests_per_minute=round(total / seconds * 60, 4),
            requests_per_hour=round(total / seconds * 3_600, 4),
            requests_per_day=round(total / seconds * 86_400, 4),
            bytes_sent=int(rows[0]["bytes"]) if rows else 0,
            top_ips=self._counts("ip_address", source, where, params, limit=top),
            top_endpoints=self._counts("endpoint", source, where, params, limit=top),
            top_user_agents=self._counts("user_agent", source, where, params, limit=top),
            top_methods=self._counts("http_method", source, where, params, limit=top),
            over_time=self.timeseries(
                "requests",
                start,
                end,
                filters,
                window=window or self.settings.analytics.default_window,
            ),
        )

    def services(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        filters: Mapping[str, Any] | None = None,
        *,
        limit: int = 50,
    ) -> ServiceAnalytics:
        """Per-service health: throughput, failure rate, availability, latency."""
        scope = self._scope(start, end, filters)
        if scope is None:
            now = utcnow()
            return ServiceAnalytics(time_range=TimeRange(start=start or now, end=end or now))
        source, where, params, time_range = scope

        sql = f"""
            SELECT service                                            AS service,
                   COUNT(*)                                           AS requests,
                   COUNT(*) FILTER (WHERE {_ERROR_PREDICATE})         AS errors,
                   AVG(response_time_ms)                              AS average,
                   MIN(response_time_ms)                              AS minimum,
                   MAX(response_time_ms)                              AS maximum,
                   approx_quantile(response_time_ms, 0.5)             AS median,
                   approx_quantile(response_time_ms, 0.95)            AS p95,
                   approx_quantile(response_time_ms, 0.99)            AS p99,
                   stddev_samp(response_time_ms)                      AS stddev,
                   SUM(response_time_ms)                              AS total
            FROM {source} WHERE {where} AND service IS NOT NULL
            GROUP BY 1 ORDER BY 2 DESC LIMIT ?
        """  # noqa: S608 - source/predicate validated, values bound
        seconds = max(time_range.seconds, 1.0)
        services: list[ServiceHealth] = []
        for row in self.engine.execute(sql, [*params, limit]):
            requests = int(row["requests"] or 0)
            errors = int(row["errors"] or 0)
            failure_rate = errors / requests if requests else 0.0
            services.append(
                ServiceHealth(
                    service=str(row["service"]),
                    requests=requests,
                    errors=errors,
                    failure_rate=round(failure_rate, 6),
                    availability=round((1 - failure_rate) * 100, 4),
                    throughput_per_second=round(requests / seconds, 4),
                    latency=_row_to_stats(row),
                    status=_health_status(failure_rate),
                )
            )
        return ServiceAnalytics(time_range=time_range, services=services)

    def timeseries(
        self,
        metric: str = "requests",
        start: datetime | None = None,
        end: datetime | None = None,
        filters: Mapping[str, Any] | None = None,
        *,
        window: str = "5m",
        fill_gaps: bool = True,
    ) -> TimeSeries:
        """Bucketed time series for one metric.

        ``time_bucket`` produces aligned buckets; gaps are filled in Python
        because a bucket with no records does not exist in the data at all, and
        an unfilled gap makes an outage look like healthy silence.
        """
        if window not in WINDOW_SQL:
            raise ValueError(f"unsupported window {window!r}; choose from {sorted(WINDOW_SQL)}")
        expression = _METRIC_EXPRESSIONS.get(metric)
        if expression is None:
            raise ValueError(
                f"unknown metric {metric!r}; choose from {sorted(_METRIC_EXPRESSIONS)}"
            )

        scope = self._scope(start, end, filters)
        if scope is None:
            return TimeSeries(metric=metric, window=window, points=[])
        source, where, params, time_range = scope

        sql = f"""
            SELECT time_bucket(INTERVAL '{WINDOW_SQL[window]}', timestamp) AS bucket,
                   {expression}                                           AS value,
                   COUNT(*)                                               AS records
            FROM {source} WHERE {where}
            GROUP BY 1 ORDER BY 1
        """  # noqa: S608 - window is looked up from a fixed table
        rows = self.engine.execute(sql, params, limit=100_000)
        buckets = {
            ensure_utc(row["bucket"]): float(row["value"] or 0.0)
            for row in rows
            if row["bucket"] is not None
        }
        counts = {
            ensure_utc(row["bucket"]): int(row["records"] or 0)
            for row in rows
            if row["bucket"] is not None
        }
        if not buckets:
            return TimeSeries(metric=metric, window=window, points=[])

        if not fill_gaps:
            points = [
                TimeSeriesPoint(bucket=bucket, value=value, count=counts.get(bucket, 0))
                for bucket, value in sorted(buckets.items())
            ]
        else:
            from app.core.timeutil import iter_windows

            points = [
                TimeSeriesPoint(
                    bucket=bucket,
                    value=buckets.get(bucket, 0.0),
                    count=counts.get(bucket, 0),
                )
                for bucket in iter_windows(time_range.start, time_range.end, window)
            ]
        return TimeSeries(metric=metric, window=window, points=points)

    def distinct_values(
        self,
        column: str,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 100,
    ) -> list[str]:
        """Distinct values of a column — powers the dashboard's filter menus."""
        scope = self._scope(start, end, None)
        if scope is None:
            return []
        source, where, params, _ = scope
        validated = validate_column(column)
        rows = self.engine.execute(
            f"SELECT DISTINCT {validated} AS value FROM {source} "  # noqa: S608
            f"WHERE {where} AND {validated} IS NOT NULL ORDER BY 1 LIMIT ?",
            [*params, limit],
        )
        return [str(row["value"]) for row in rows]

    def close(self) -> None:
        self.engine.close()


# --------------------------------------------------------------------------- #
# SQL fragments
# --------------------------------------------------------------------------- #
_STATS_SELECT: Final[str] = """
    COUNT(response_time_ms)                    AS count,
    COALESCE(SUM(response_time_ms), 0)         AS total,
    AVG(response_time_ms)                      AS average,
    MIN(response_time_ms)                      AS minimum,
    MAX(response_time_ms)                      AS maximum,
    approx_quantile(response_time_ms, 0.5)     AS median,
    approx_quantile(response_time_ms, 0.95)    AS p95,
    approx_quantile(response_time_ms, 0.99)    AS p99,
    stddev_samp(response_time_ms)              AS stddev
"""

#: Metric name → SQL aggregate.  A closed map: a metric name from a request can
#: only ever select one of these, never inject SQL.
_METRIC_EXPRESSIONS: Final[dict[str, str]] = {
    "requests": "COUNT(*)",
    "errors": f"COUNT(*) FILTER (WHERE {_ERROR_PREDICATE})",
    "error_rate": (
        f"COALESCE(COUNT(*) FILTER (WHERE {_ERROR_PREDICATE}) * 1.0 / NULLIF(COUNT(*), 0), 0)"
    ),
    "server_errors": "COUNT(*) FILTER (WHERE status_code >= 500)",
    "client_errors": "COUNT(*) FILTER (WHERE status_code >= 400 AND status_code < 500)",
    "latency_avg": "COALESCE(AVG(response_time_ms), 0)",
    "latency_p95": "COALESCE(approx_quantile(response_time_ms, 0.95), 0)",
    "latency_p99": "COALESCE(approx_quantile(response_time_ms, 0.99), 0)",
    "latency_max": "COALESCE(MAX(response_time_ms), 0)",
    "bytes": "COALESCE(SUM(bytes_sent), 0)",
    "unique_ips": "COUNT(DISTINCT ip_address)",
    "unique_users": "COUNT(DISTINCT user_id)",
}

AVAILABLE_METRICS: Final[tuple[str, ...]] = tuple(sorted(_METRIC_EXPRESSIONS))


def _row_to_stats(row: Mapping[str, Any]) -> Stats:
    def number(key: str) -> float:
        value = row.get(key)
        return round(float(value), 6) if value is not None else 0.0

    return Stats(
        count=int(row.get("count") or 0),
        sum=number("total"),
        average=number("average"),
        minimum=number("minimum"),
        maximum=number("maximum"),
        median=number("median"),
        p95=number("p95"),
        p99=number("p99"),
        stddev=number("stddev"),
    )


def _health_status(failure_rate: float) -> str:
    if failure_rate >= UNHEALTHY_FAILURE_RATE:
        return "unhealthy"
    if failure_rate >= DEGRADED_FAILURE_RATE:
        return "degraded"
    return "healthy"


__all__ = ["AVAILABLE_METRICS", "ERROR_LEVELS", "AnalyticsEngine"]
