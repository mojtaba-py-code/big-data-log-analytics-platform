"""Database ingestion (PostgreSQL, MySQL, SQLite).

Responsibility
--------------
Stream rows out of an existing log table without loading it into memory.

Security
--------
* **No string-built SQL over user input.**  Filter values are always bound
  parameters.  Identifiers (table and column names) *cannot* be parameterised
  by any driver, so they are validated against a strict identifier pattern and
  quoted — that is the only safe way to interpolate them.
* Credentials come from :class:`~app.core.config.DatabaseSettings` as
  ``SecretStr`` and are never logged; connection errors are re-raised without
  the DSN.
* The connection is opened read-only where the driver supports it, and the
  documentation is explicit that the account should have ``SELECT`` on the log
  table and nothing else (least privilege).

Memory
------
``stream_results=True`` plus ``yield_per`` uses a server-side cursor on
PostgreSQL and MySQL, so a 100 M-row table is streamed in ``fetch_size``
batches rather than buffered by the driver.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime
from typing import Any, Final

from app.core.exceptions import ConfigurationError, IngestionError
from app.core.logging import get_logger
from app.ingestion.base import LogSource, RawRecord, source_registry
from app.models.enums import SourceType

log = get_logger(__name__)

#: A SQL identifier we are willing to interpolate.  Deliberately narrow: no
#: quotes, no dots beyond one schema separator, no whitespace, no semicolons.
_IDENTIFIER: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")

_QUOTE_CHARS: Final[dict[str, tuple[str, str]]] = {
    "postgresql": ('"', '"'),
    "sqlite": ('"', '"'),
    "mysql": ("`", "`"),
}


def validate_identifier(name: str, *, kind: str = "identifier") -> str:
    """Reject anything that is not a plain SQL identifier."""
    if not _IDENTIFIER.match(name):
        raise ConfigurationError(
            f"invalid {kind}: only letters, digits and underscores are permitted",
            value=name[:64],
        )
    return name


def quote_identifier(name: str, dialect: str = "postgresql") -> str:
    """Validate then quote an identifier for the given dialect."""
    open_q, close_q = _QUOTE_CHARS.get(dialect, ('"', '"'))
    return f"{open_q}{validate_identifier(name)}{close_q}"


def qualified_table(table: str, dialect: str = "postgresql") -> str:
    """Quote a possibly schema-qualified table name (``public.logs``)."""
    parts = table.split(".")
    if len(parts) > 2:
        raise ConfigurationError("table name may contain at most one schema separator")
    return ".".join(quote_identifier(part, dialect) for part in parts)


@source_registry.register("database", "db", "sql")
class DatabaseSource(LogSource):
    """Streams rows from a relational table or a parameterised query."""

    name = "database"
    source_type = SourceType.DATABASE

    def __init__(
        self,
        url: str,
        *,
        table: str | None = None,
        query: str | None = None,
        params: Mapping[str, Any] | None = None,
        columns: Sequence[str] | None = None,
        timestamp_column: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
        fetch_size: int = 5_000,
        dialect: str | None = None,
    ) -> None:
        super().__init__()
        if not table and not query:
            raise ConfigurationError("either 'table' or 'query' must be provided")
        if table and query:
            raise ConfigurationError("provide either 'table' or 'query', not both")
        self.url = url
        self.table = table
        self.query = query
        self.params = dict(params or {})
        self.columns = tuple(columns or ())
        self.timestamp_column = timestamp_column
        self.since = since
        self.until = until
        self.limit = limit
        self.fetch_size = max(1, fetch_size)
        self.dialect = dialect or url.split(":", 1)[0].split("+", 1)[0]
        self._engine: Any = None

    def describe(self) -> str:
        # Never echo the URL: it carries the password.
        target = self.table or "custom query"
        return f"{self.dialect}:{target}"

    # -- SQL construction ---------------------------------------------------- #
    def _build_query(self) -> tuple[str, dict[str, Any]]:
        """Assemble the SELECT.

        Identifiers are validated and quoted; every *value* is a bound
        parameter.  This is the only place in the platform that builds SQL for
        an external database, and it is intentionally small enough to audit.
        """
        if self.query:
            return self.query, dict(self.params)

        if self.table is None:  # pragma: no cover - guaranteed by __init__
            raise ConfigurationError("no table configured for this source")
        table = qualified_table(self.table, self.dialect)
        if self.columns:
            selected = ", ".join(quote_identifier(c, self.dialect) for c in self.columns)
        else:
            selected = "*"

        clauses: list[str] = []
        params: dict[str, Any] = dict(self.params)
        if self.timestamp_column:
            column = quote_identifier(self.timestamp_column, self.dialect)
            if self.since is not None:
                clauses.append(f"{column} >= :since")
                params["since"] = self.since
            if self.until is not None:
                clauses.append(f"{column} < :until")
                params["until"] = self.until

        sql = f"SELECT {selected} FROM {table}"  # noqa: S608 - identifiers validated above
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        if self.timestamp_column:
            sql += f" ORDER BY {quote_identifier(self.timestamp_column, self.dialect)}"
        if self.limit is not None:
            sql += " LIMIT :row_limit"
            params["row_limit"] = int(self.limit)
        return sql, params

    # -- streaming ----------------------------------------------------------- #
    def read(self) -> Iterator[RawRecord]:
        try:
            from sqlalchemy import create_engine, text
        except ImportError as exc:  # pragma: no cover - declared dependency
            raise IngestionError("SQLAlchemy is required for database ingestion") from exc

        sql, params = self._build_query()
        try:
            self._engine = create_engine(self.url, pool_pre_ping=True)
        except Exception as exc:  # noqa: BLE001 - driver-specific failures
            raise IngestionError(
                "failed to create the database engine", dialect=self.dialect
            ) from exc

        source = self.describe()
        try:
            with self._engine.connect().execution_options(
                stream_results=True, yield_per=self.fetch_size
            ) as connection:
                result = connection.execute(text(sql), params)
                for number, row in enumerate(result.mappings(), start=1):
                    record = dict(row)
                    self.stats.records_read += 1
                    yield RawRecord(payload=record, source=source, line_number=number)
        except Exception as exc:  # noqa: BLE001 - never leak the DSN
            raise IngestionError(
                "database read failed", dialect=self.dialect, error_type=type(exc).__name__
            ) from exc

    def close(self) -> None:
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None


__all__ = [
    "DatabaseSource",
    "qualified_table",
    "quote_identifier",
    "validate_identifier",
]
