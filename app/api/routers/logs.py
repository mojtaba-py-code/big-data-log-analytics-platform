"""Log query endpoints.

``GET /logs``            filtered, sorted, paginated listing
``GET /logs/search``     the full query language
``GET /logs/{event_id}`` one record
``GET /logs/fields/{f}`` value suggestions for filter UIs

Every parameter is validated by FastAPI before it reaches the service, and the
free-form ``q`` goes through the search compiler, which emits only bound
parameters (see :mod:`app.search.query`).
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from app.api.deps import FilterParams, PaginationParams, TimeRangeParams, get_search
from app.api.security import RequireRead
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.models.log_event import QUERYABLE_COLUMNS
from app.search.query import compile_query
from app.search.service import SearchService

log = get_logger(__name__)

router = APIRouter(prefix="/logs", tags=["logs"], dependencies=[RequireRead])

_SORTABLE = sorted(QUERYABLE_COLUMNS)


@router.get("", summary="List log records")
async def list_logs(
    time_range: Annotated[TimeRangeParams, Depends()],
    pagination: Annotated[PaginationParams, Depends()],
    filters: Annotated[FilterParams, Depends()],
    search: Annotated[SearchService, Depends(get_search)],
    sort_by: Annotated[str, Query(description=f"One of: {', '.join(_SORTABLE)}")] = "timestamp",
    sort_order: Annotated[str, Query(pattern="^(?i)(asc|desc)$")] = "desc",
) -> dict[str, Any]:
    """Filtered, sorted, paginated log listing."""
    result = search.search(
        filters=filters.active(),
        start=time_range.start,
        end=time_range.end,
        page=pagination.page,
        page_size=pagination.page_size,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return result.as_dict()


@router.get("/search", summary="Search logs with the query language")
async def search_logs(
    time_range: Annotated[TimeRangeParams, Depends()],
    pagination: Annotated[PaginationParams, Depends()],
    search: Annotated[SearchService, Depends(get_search)],
    q: Annotated[
        str,
        Query(
            max_length=4_096,
            description=(
                "Query expression, e.g. `service=payment AND level=ERROR`, "
                "`status_code>=500`, `endpoint~/api/*`, or bare text for a "
                "full-text match on the message."
            ),
        ),
    ] = "",
    filters: Annotated[FilterParams, Depends()] = None,  # type: ignore[assignment]
    sort_by: Annotated[str, Query()] = "timestamp",
    sort_order: Annotated[str, Query(pattern="^(?i)(asc|desc)$")] = "desc",
    explain: Annotated[bool, Query(description="Return the compiled predicate.")] = False,
) -> dict[str, Any]:
    """Full search.

    Syntax errors are returned as 400 with a message describing the *client's*
    input — the one class of error detail that is always safe to echo back.
    """
    if explain:
        return {"explain": compile_query(q).describe()}
    result = search.search(
        q,
        filters=filters.active() if filters else None,
        start=time_range.start,
        end=time_range.end,
        page=pagination.page,
        page_size=pagination.page_size,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return result.as_dict()


@router.get("/fields", summary="Searchable fields")
async def fields() -> dict[str, Any]:
    """The field allow-list, for building a query UI."""
    from app.search.query import FIELD_ALIASES

    return {"fields": _SORTABLE, "aliases": FIELD_ALIASES}


@router.get("/fields/{field_name}/values", summary="Suggest values for a field")
async def field_values(
    search: Annotated[SearchService, Depends(get_search)],
    field_name: Annotated[str, Path(max_length=64)],
    prefix: Annotated[str, Query(max_length=128)] = "",
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> dict[str, Any]:
    """Autocomplete values for a filter field."""
    return {"field": field_name, "values": search.suggest(field_name, prefix, limit)}


@router.get("/{event_id}", summary="Fetch one record")
async def get_log(
    search: Annotated[SearchService, Depends(get_search)],
    event_id: Annotated[str, Path(min_length=8, max_length=64, pattern="^[A-Za-z0-9_-]+$")],
) -> dict[str, Any]:
    """One record by its deterministic event id."""
    record = search.get_by_id(event_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="record not found")
    return record


@router.get("/export/stream", summary="Stream a filtered export")
async def export_logs(
    time_range: Annotated[TimeRangeParams, Depends()],
    filters: Annotated[FilterParams, Depends()],
    search: Annotated[SearchService, Depends(get_search)],
    settings: Annotated[Settings, Depends(get_settings)],
    q: Annotated[str, Query(max_length=4_096)] = "",
    limit: Annotated[int, Query(ge=1, le=100_000)] = 10_000,
) -> Any:
    """Stream matching records as JSONL.

    Streamed rather than assembled: a 100 k-record export must not be built in
    memory, and the client starts receiving data immediately.  The hard cap
    exists so one request cannot pin a worker indefinitely.
    """
    import json

    from fastapi.responses import StreamingResponse

    page_size = min(1_000, settings.api.max_page_size)

    def generate() -> Any:
        emitted = 0
        page = 1
        while emitted < limit:
            result = search.search(
                q,
                filters=filters.active(),
                start=time_range.start,
                end=time_range.end,
                page=page,
                page_size=min(page_size, limit - emitted),
                count_total=False,
            )
            if not result.items:
                return
            for item in result.items:
                yield json.dumps(item, default=str) + "\n"
                emitted += 1
            page += 1

    return StreamingResponse(
        generate(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": 'attachment; filename="logs-export.jsonl"'},
    )


__all__ = ["router"]
