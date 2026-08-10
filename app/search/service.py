"""Search service.

Turns a compiled query into paginated results against the processed dataset.

Pagination
----------
Offset pagination is used because the UI needs random access to pages and the
underlying scan is already bounded by partition pruning.  The total count is
computed with a second query and is *cached by the caller*, not recomputed for
every page — counting is the expensive half of pagination.

For deep pagination (offset beyond ~50 k) offset scanning degrades; the service
exposes ``search_after`` for keyset pagination, which stays constant-time by
seeking on ``(timestamp, event_id)`` instead of skipping rows.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.timeutil import parse_range, to_iso
from app.search.query import CompiledQuery, combine, compile_filters, compile_query
from app.storage.duckdb_engine import DuckDBEngine, validate_column, validate_direction

log = get_logger(__name__)

DEFAULT_COLUMNS: tuple[str, ...] = (
    "timestamp",
    "level",
    "service",
    "hostname",
    "message",
    "ip_address",
    "http_method",
    "endpoint",
    "status_code",
    "response_time_ms",
    "request_id",
    "user_id",
    "event_id",
)


@dataclass(slots=True)
class SearchResult:
    """One page of results plus the metadata a client needs to paginate."""

    items: list[dict[str, Any]]
    total: int
    page: int
    page_size: int
    query: str = ""
    took_ms: float = 0.0
    truncated: bool = False

    @property
    def pages(self) -> int:
        return (self.total + self.page_size - 1) // self.page_size if self.page_size else 0

    @property
    def has_more(self) -> bool:
        return self.page * self.page_size < self.total

    def as_dict(self) -> dict[str, Any]:
        return {
            "items": self.items,
            "pagination": {
                "page": self.page,
                "page_size": self.page_size,
                "total": self.total,
                "pages": self.pages,
                "has_more": self.has_more,
            },
            "query": self.query,
            "took_ms": round(self.took_ms, 3),
            "truncated": self.truncated,
        }


class SearchService:
    """Executes search queries against the processed dataset."""

    def __init__(
        self, engine: DuckDBEngine | None = None, settings: Settings | None = None
    ) -> None:
        self.settings = settings or get_settings()
        if engine is None:
            from app.storage import build_engine

            engine = build_engine(self.settings)
        self.engine = engine

    def search(
        self,
        query: str = "",
        *,
        filters: Mapping[str, Any] | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        page: int = 1,
        page_size: int = 50,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
        columns: Sequence[str] | None = None,
        count_total: bool = True,
    ) -> SearchResult:
        """Run a search and return one page of results."""
        import time

        started = time.perf_counter()
        page = max(1, page)
        page_size = max(1, min(page_size, self.settings.api.max_page_size))
        start_dt, end_dt = parse_range(start, end)

        compiled = combine(
            compile_query(query),
            compile_filters(dict(filters or {})),
        )
        selected = list(columns or DEFAULT_COLUMNS)

        rows = self.engine.query_logs(
            compiled.sql,
            compiled.params,
            start=start_dt,
            end=end_dt,
            columns=selected,
            order_by=validate_column(sort_by),
            direction=validate_direction(sort_order),
            limit=page_size,
            offset=(page - 1) * page_size,
        )
        total = (
            self.engine.count_logs(compiled.sql, compiled.params, start=start_dt, end=end_dt)
            if count_total
            else len(rows) + (page - 1) * page_size
        )

        took = (time.perf_counter() - started) * 1000
        log.info(
            "search executed",
            extra={
                "query": compiled.text[:200],
                "results": len(rows),
                "total": total,
                "took_ms": round(took, 2),
            },
        )
        return SearchResult(
            items=[_serialise(row) for row in rows],
            total=total,
            page=page,
            page_size=page_size,
            query=compiled.text,
            took_ms=took,
            truncated=total > self.settings.analytics.max_query_rows,
        )

    def search_after(
        self,
        query: str = "",
        *,
        after_timestamp: datetime | None = None,
        after_event_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        page_size: int = 50,
        columns: Sequence[str] | None = None,
    ) -> SearchResult:
        """Keyset pagination — constant-time regardless of how deep you scroll.

        Offset pagination has to scan and discard every skipped row; seeking on
        the sort key does not.  The cursor is ``(timestamp, event_id)``, and the
        event id breaks ties so no record is skipped or repeated when many
        records share a timestamp.
        """
        start_dt, end_dt = parse_range(start, end)
        compiled = compile_query(query)
        clauses: list[str] = []
        params: list[Any] = []
        if compiled.sql:
            clauses.append(f"({compiled.sql})")
            params.extend(compiled.params)
        if after_timestamp is not None:
            clauses.append("(timestamp < ? OR (timestamp = ? AND event_id < ?))")
            params.extend([after_timestamp, after_timestamp, after_event_id or ""])
        predicate = " AND ".join(clauses)

        rows = self.engine.query_logs(
            predicate,
            params,
            start=start_dt,
            end=end_dt,
            columns=list(columns or DEFAULT_COLUMNS),
            order_by="timestamp",
            direction="DESC",
            limit=page_size,
        )
        return SearchResult(
            items=[_serialise(row) for row in rows],
            total=len(rows),
            page=1,
            page_size=page_size,
            query=compiled.text,
        )

    def get_by_id(self, event_id: str) -> dict[str, Any] | None:
        """Fetch a single record by its deterministic id."""
        rows = self.engine.query_logs("event_id = ?", [event_id], limit=1)
        return _serialise(rows[0]) if rows else None

    def suggest(self, field_name: str, prefix: str = "", limit: int = 20) -> list[str]:
        """Autocomplete values for a field — powers the dashboard's filters."""
        from app.search.query import resolve_column

        column = resolve_column(field_name)
        scan = self.engine.scan()
        if scan is None:
            return []
        source, params = scan
        clauses = [f"{column} IS NOT NULL"]
        if prefix:
            from app.search.query import _escape_like

            clauses.append(f"{column}::VARCHAR ILIKE ? ESCAPE '\\'")
            params.append(f"{_escape_like(prefix)}%")
        rows = self.engine.execute(
            f"SELECT DISTINCT {column} AS value FROM {source} "  # noqa: S608 - allow-listed
            f"WHERE {' AND '.join(clauses)} ORDER BY 1 LIMIT ?",
            [*params, min(limit, 100)],
        )
        return [str(row["value"]) for row in rows]

    def close(self) -> None:
        self.engine.close()


def _serialise(row: Mapping[str, Any]) -> dict[str, Any]:
    """JSON-safe row: datetimes become ISO-8601 UTC strings."""
    return {
        key: to_iso(value) if isinstance(value, datetime) else value for key, value in row.items()
    }


__all__ = ["DEFAULT_COLUMNS", "CompiledQuery", "SearchResult", "SearchService"]
