"""DuckDB analytical engine.

Responsibility
--------------
Execute analytical SQL directly against the partitioned Parquet dataset.  There
is no "load into a database" step: DuckDB reads Parquet natively, pushes
filters and projections down into the files, and streams results.

Why DuckDB
----------
* **No server.**  The CLI, the API and the tests all use the same engine with
  zero operational cost.
* **Out-of-core.**  With ``memory_limit`` set, aggregations larger than RAM
  spill to disk instead of failing — a 10 M-record group-by works on a laptop.
* **Predicate and projection push-down.**  A ``WHERE timestamp >= ?`` is
  evaluated against Parquet row-group statistics, so most data is never read.
* **Correct SQL.**  Window functions, ``approx_quantile``, ``time_bucket`` —
  the analytics layer stays declarative instead of re-implementing statistics
  in Python loops.

Security
--------
Every value is a **bound parameter** (``?``); no user input is ever
concatenated into SQL.  The only interpolated fragments are column names, and
those are validated against
:data:`app.models.log_event.QUERYABLE_COLUMNS` first — an allow-list, not an
escape function.  File globs come from the platform's own partition layout,
never from a request.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from app.core.exceptions import QueryError
from app.core.logging import get_logger
from app.models.log_event import QUERYABLE_COLUMNS
from app.storage.partitioning import glob_for_range

log = get_logger(__name__)

#: The scan target.  ``?`` is bound to the list of Parquet globs, so not
#: even a file path is interpolated into the SQL text — which also means a
#: data root containing a quote cannot break the statement.
SOURCE_FRAGMENT: Final[str] = "read_parquet(?, union_by_name=true, hive_partitioning=true)"

#: Hard ceiling on rows returned to a caller, regardless of what it asks for.
ABSOLUTE_MAX_ROWS: Final[int] = 1_000_000


def validate_column(name: str) -> str:
    """Allow-list check for anything interpolated as an identifier."""
    if name not in QUERYABLE_COLUMNS:
        raise QueryError(f"unknown column {name!r}", column=name)
    return name


def validate_direction(direction: str) -> str:
    upper = direction.strip().upper()
    if upper not in {"ASC", "DESC"}:
        raise QueryError("sort direction must be ASC or DESC", direction=direction)
    return upper


class DuckDBEngine:
    """Thin, safe wrapper around a DuckDB connection over the Parquet dataset.

    Thread-safety: DuckDB connections are not thread-safe for concurrent use,
    so access is serialised with a lock.  For the API this is fine — queries
    are short and DuckDB itself parallelises each one across cores.
    """

    def __init__(
        self,
        dataset_root: Path,
        *,
        memory_limit_mb: int = 512,
        threads: int = 2,
        temp_directory: Path | None = None,
        read_only_files: bool = True,
    ) -> None:
        self.dataset_root = Path(dataset_root)
        self.memory_limit_mb = memory_limit_mb
        self.threads = max(1, threads)
        self.temp_directory = temp_directory
        self.read_only_files = read_only_files
        self._connection: Any = None
        self._lock = threading.RLock()

    # -- connection --------------------------------------------------------- #
    def _connect(self) -> Any:
        if self._connection is not None:
            return self._connection
        try:
            import duckdb
        except ImportError as exc:  # pragma: no cover - declared dependency
            raise QueryError("duckdb is required for analytical queries") from exc

        connection = duckdb.connect(database=":memory:")
        # Without this, DuckDB renders TIMESTAMPTZ in the *host's* timezone and
        # every bucket boundary silently shifts with the server's locale.
        connection.execute("SET TimeZone='UTC'")
        # Spilling to disk beats an OOM kill: a 6 GB laptop can still aggregate
        # a dataset much larger than RAM.
        connection.execute(f"SET memory_limit='{self.memory_limit_mb}MB'")
        connection.execute(f"SET threads={self.threads}")
        if self.temp_directory is not None:
            self.temp_directory.mkdir(parents=True, exist_ok=True)
            # DuckDB's SET takes no bind parameters, so the path is escaped the
            # only way a SQL string literal can be: by doubling its quotes.
            # A data root containing an apostrophe is unusual but legal.
            literal = self.temp_directory.as_posix().replace("'", "''")
            connection.execute(f"SET temp_directory='{literal}'")  # noqa: S608
        if self.read_only_files:
            # Defence in depth: the engine only ever needs to read local files.
            for statement in (
                "SET enable_external_access=true",
                "SET autoinstall_known_extensions=false",
                "SET autoload_known_extensions=false",
            ):
                try:
                    connection.execute(statement)
                except Exception:  # noqa: BLE001 - option name varies by version
                    log.debug("duckdb option not supported: %s", statement)
        self._connection = connection
        return connection

    @contextmanager
    def connection(self) -> Iterator[Any]:
        with self._lock:
            yield self._connect()

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    # -- dataset scope ------------------------------------------------------ #
    def scan(
        self, start: datetime | None = None, end: datetime | None = None
    ) -> tuple[str, list[Any]] | None:
        """The SQL scan fragment and the parameters it needs.

        Returns ``(fragment, params)`` where ``params`` already contains the
        pruned file list as its first bound value, or ``None`` when no
        partition matches — so callers can answer "no data" without
        executing anything.

        Callers must place these parameters *first*, because the scan
        appears in the ``FROM`` clause before any predicate.
        """
        globs = [g.replace(chr(92), "/") for g in glob_for_range(self.dataset_root, start, end)]
        if not globs:
            return None
        return SOURCE_FRAGMENT, [globs]

    def source_expression(
        self, start: datetime | None = None, end: datetime | None = None
    ) -> str | None:
        """The scan fragment alone, or ``None`` when there is no data."""
        scan = self.scan(start, end)
        return scan[0] if scan else None

    def has_data(self, start: datetime | None = None, end: datetime | None = None) -> bool:
        return self.scan(start, end) is not None

    # -- execution ---------------------------------------------------------- #
    def execute(
        self,
        sql: str,
        params: Sequence[Any] = (),
        *,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Run a parameterised query and return rows as dicts."""
        effective_limit = min(limit or ABSOLUTE_MAX_ROWS, ABSOLUTE_MAX_ROWS)
        with self.connection() as connection:
            try:
                cursor = connection.execute(sql, list(params))
                columns = [description[0] for description in cursor.description or []]
                rows = cursor.fetchmany(effective_limit)
            except Exception as exc:  # noqa: BLE001 - duckdb raises many types
                # The SQL is ours; the message may still quote a parameter, so
                # it is logged rather than returned to the caller.
                log.warning(
                    "query failed",
                    extra={"error_type": type(exc).__name__, "detail": str(exc)[:300]},
                )
                raise QueryError("the analytical query failed") from exc
        return [dict(zip(columns, row, strict=False)) for row in rows]

    def execute_scalar(self, sql: str, params: Sequence[Any] = ()) -> Any:
        rows = self.execute(sql, params, limit=1)
        if not rows:
            return None
        return next(iter(rows[0].values()))

    def query_logs(
        self,
        where: str = "",
        params: Sequence[Any] = (),
        *,
        start: datetime | None = None,
        end: datetime | None = None,
        columns: Sequence[str] | None = None,
        order_by: str = "timestamp",
        direction: str = "DESC",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Fetch log rows with a caller-supplied (already validated) predicate.

        ``where`` must contain only ``?`` placeholders for values — it is built
        by :mod:`app.search.query` from a validated AST, never by string
        concatenation of user text.
        """
        scan = self.scan(start, end)
        if scan is None:
            return []
        source, values = scan
        selected = (
            ", ".join(validate_column(c) for c in columns)
            if columns
            else ", ".join(sorted(QUERYABLE_COLUMNS))
        )
        order_column = validate_column(order_by)
        order_direction = validate_direction(direction)

        clauses: list[str] = []
        if start is not None:
            clauses.append("timestamp >= ?")
            values.append(start)
        if end is not None:
            clauses.append("timestamp <= ?")
            values.append(end)
        if where:
            clauses.append(f"({where})")
            values.extend(params)
        predicate = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        sql = (
            f"SELECT {selected} FROM {source} {predicate} "  # noqa: S608 - identifiers validated
            f"ORDER BY {order_column} {order_direction} LIMIT ? OFFSET ?"
        )
        values.extend([min(limit, ABSOLUTE_MAX_ROWS), max(0, offset)])
        return self.execute(sql, values, limit=limit)

    def count_logs(
        self,
        where: str = "",
        params: Sequence[Any] = (),
        *,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> int:
        """Row count for the same predicate — used for pagination totals."""
        scan = self.scan(start, end)
        if scan is None:
            return 0
        source, values = scan
        clauses: list[str] = []
        if start is not None:
            clauses.append("timestamp >= ?")
            values.append(start)
        if end is not None:
            clauses.append("timestamp <= ?")
            values.append(end)
        if where:
            clauses.append(f"({where})")
            values.extend(params)
        predicate = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT COUNT(*) FROM {source} {predicate}"  # noqa: S608 - see above
        return int(self.execute_scalar(sql, values) or 0)

    def dataset_summary(self) -> dict[str, Any]:
        """Coarse dataset statistics for ``/health`` and ``loganalytics stats``."""
        scan = self.scan()
        if scan is None:
            return {"records": 0, "first_event": None, "last_event": None, "services": 0}
        source, params = scan
        sql = (
            "SELECT COUNT(*) AS records, MIN(timestamp) AS first_event, "  # noqa: S608 - identifiers are allow-listed, values are bound (see module docstring)
            "MAX(timestamp) AS last_event, COUNT(DISTINCT service) AS services "
            f"FROM {source}"  # noqa: S608 - constant fragment, file list is bound
        )
        rows = self.execute(sql, params, limit=1)
        return rows[0] if rows else {"records": 0}


__all__ = [
    "ABSOLUTE_MAX_ROWS",
    "SOURCE_FRAGMENT",
    "DuckDBEngine",
    "validate_column",
    "validate_direction",
]
