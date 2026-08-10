"""Transactional metadata store.

Responsibility
--------------
Parquet holds the *data*; this holds the *facts about the data*: which runs
happened, what they produced, where each source was last read up to, and which
API credentials exist.  It is small, highly transactional and read-modify-write
— exactly what a relational database is for and what a columnar file store is
not.

SQLite by default, PostgreSQL in production; the interface is identical because
it goes through SQLAlchemy.

Idempotency
-----------
:class:`IngestCheckpoint` records ``(source, last_offset, last_timestamp)`` so a
re-run resumes rather than re-processing.  Combined with deterministic
``event_id``s, re-running a failed job is safe: records that do get re-written
overwrite themselves instead of duplicating.

Security
--------
API keys are stored **hashed** (SHA-256 of a high-entropy random token), never
in plaintext.  The plaintext is shown once at creation and cannot be recovered
— the same model every serious platform uses, and the reason a database leak
does not become an authentication bypass.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.core.exceptions import StorageError
from app.core.hashing import generate_api_key, hash_secret, verify_secret
from app.core.logging import get_logger
from app.core.timeutil import ensure_utc, utcnow
from app.models.enums import JobStatus
from app.models.results import PipelineResult

log = get_logger(__name__)


class Base(DeclarativeBase):
    """Declarative base for the metadata schema."""


class JobRun(Base):
    """One pipeline execution."""

    __tablename__ = "job_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    job_type: Mapped[str] = mapped_column(String(32), default="ingest", index=True)
    status: Mapped[str] = mapped_column(String(16), default=JobStatus.PENDING, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sources: Mapped[str] = mapped_column(Text, default="")
    lines_read: Mapped[int] = mapped_column(Integer, default=0)
    records_written: Mapped[int] = mapped_column(Integer, default=0)
    records_rejected: Mapped[int] = mapped_column(Integer, default=0)
    records_duplicate: Mapped[int] = mapped_column(Integer, default=0)
    bytes_read: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "job_type": self.job_type,
            "status": self.status,
            # Re-normalised because SQLite returns naive datetimes for columns
            # that were written as timezone-aware.
            "started_at": ensure_utc(self.started_at) if self.started_at else None,
            "finished_at": ensure_utc(self.finished_at) if self.finished_at else None,
            "sources": json.loads(self.sources) if self.sources else [],
            "lines_read": self.lines_read,
            "records_written": self.records_written,
            "records_rejected": self.records_rejected,
            "records_duplicate": self.records_duplicate,
            "bytes_read": self.bytes_read,
            "duration_seconds": self.duration_seconds,
            "details": self.details or {},
            "error": self.error,
        }


class IngestCheckpoint(Base):
    """How far a given source has been processed."""

    __tablename__ = "ingest_checkpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(1024), unique=True, index=True)
    last_offset: Mapped[int] = mapped_column(Integer, default=0)
    last_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class ApiKeyRecord(Base):
    """A hashed API credential with its scopes."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scopes: Mapped[str] = mapped_column(String(512), default="read")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def scope_set(self) -> set[str]:
        return {s.strip() for s in self.scopes.split(",") if s.strip()}


class MetadataStore:
    """Session factory plus the handful of operations the platform needs."""

    def __init__(self, url: str, *, echo: bool = False, pool_size: int = 5) -> None:
        self.url = url
        kwargs: dict[str, Any] = {"echo": echo, "future": True}
        if not url.startswith("sqlite"):
            kwargs.update({"pool_size": pool_size, "pool_pre_ping": True})
        try:
            self.engine = create_engine(url, **kwargs)
        except Exception as exc:  # noqa: BLE001 - never leak the DSN
            raise StorageError("failed to create the metadata engine") from exc
        self._session_factory = sessionmaker(self.engine, expire_on_commit=False)

    @classmethod
    def from_settings(cls, settings: Any) -> MetadataStore:
        database = settings.database
        if database.driver == "sqlite":
            database.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        return cls(database.url(), echo=database.echo, pool_size=database.pool_size)

    def create_schema(self) -> None:
        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Transactional scope: commit on success, roll back on any error."""
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # -- job runs ----------------------------------------------------------- #
    def start_run(self, run_id: str, job_type: str = "ingest", sources: Sequence[str] = ()) -> None:
        with self.session() as session:
            session.add(
                JobRun(
                    run_id=run_id,
                    job_type=job_type,
                    status=JobStatus.RUNNING,
                    sources=json.dumps(list(sources)),
                )
            )

    def finish_run(self, result: PipelineResult, *, error: str | None = None) -> None:
        with self.session() as session:
            run = session.scalar(select(JobRun).where(JobRun.run_id == result.run_id))
            if run is None:
                run = JobRun(run_id=result.run_id)
                session.add(run)
            run.status = JobStatus.SUCCEEDED if result.succeeded and not error else JobStatus.FAILED
            run.finished_at = result.finished_at or utcnow()
            run.sources = json.dumps(result.sources)
            run.lines_read = result.lines_read
            run.records_written = result.records_written
            run.records_rejected = result.records_rejected
            run.records_duplicate = result.records_duplicate
            run.bytes_read = result.bytes_read
            run.duration_seconds = result.duration_seconds
            run.details = result.summary()
            run.error = error

    def recent_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.session() as session:
            rows = session.scalars(
                select(JobRun).order_by(JobRun.started_at.desc()).limit(limit)
            ).all()
            return [row.as_dict() for row in rows]

    def run_stats(self) -> dict[str, Any]:
        with self.session() as session:
            total = session.scalar(select(func.count()).select_from(JobRun)) or 0
            failed = (
                session.scalar(
                    select(func.count())
                    .select_from(JobRun)
                    .where(JobRun.status == JobStatus.FAILED)
                )
                or 0
            )
            records = (
                session.scalar(select(func.coalesce(func.sum(JobRun.records_written), 0))) or 0
            )
            return {"runs": total, "failed_runs": failed, "records_written": int(records)}

    # -- checkpoints -------------------------------------------------------- #
    def get_checkpoint(self, source: str) -> IngestCheckpoint | None:
        with self.session() as session:
            return session.scalar(select(IngestCheckpoint).where(IngestCheckpoint.source == source))

    def save_checkpoint(
        self,
        source: str,
        *,
        last_offset: int,
        last_timestamp: datetime | None = None,
        run_id: str | None = None,
    ) -> None:
        with self.session() as session:
            checkpoint = session.scalar(
                select(IngestCheckpoint).where(IngestCheckpoint.source == source)
            )
            if checkpoint is None:
                checkpoint = IngestCheckpoint(source=source)
                session.add(checkpoint)
            checkpoint.last_offset = last_offset
            checkpoint.last_timestamp = last_timestamp
            checkpoint.last_run_id = run_id

    # -- API keys ----------------------------------------------------------- #
    def create_api_key(self, name: str, scopes: Sequence[str] = ("read",)) -> str:
        """Mint a key.  The plaintext is returned **once** and never stored."""
        secret = generate_api_key()
        with self.session() as session:
            session.add(
                ApiKeyRecord(name=name, key_hash=hash_secret(secret), scopes=",".join(scopes))
            )
        log.info("api key created", extra={"key_name": name, "scopes": list(scopes)})
        return secret

    #: How stale ``last_used_at`` may get before it is written again.  Updating
    #: it on every request turns each read into a database write with an fsync —
    #: ~14 ms on SQLite, which alone caps the API at a few dozen requests per
    #: second.  Minute granularity is all "when was this key last used?" needs.
    LAST_USED_RESOLUTION = timedelta(minutes=1)

    def verify_api_key(self, presented: str) -> ApiKeyRecord | None:
        """Constant-time verification against every active key."""
        with self.session() as session:
            candidates = session.scalars(
                select(ApiKeyRecord).where(ApiKeyRecord.active.is_(True))
            ).all()
            for record in candidates:
                if verify_secret(presented, record.key_hash):
                    now = utcnow()
                    # SQLite has no timezone type, so a value written as aware
                    # comes back naive.  Comparing the two raises, so every
                    # datetime read back from the store is re-normalised.
                    last_used = ensure_utc(record.last_used_at) if record.last_used_at else None
                    if last_used is None or now - last_used > self.LAST_USED_RESOLUTION:
                        record.last_used_at = now
                    else:
                        # Nothing changed, so the session commits nothing.
                        session.expunge(record)
                    return record
        return None

    def revoke_api_key(self, name: str) -> bool:
        with self.session() as session:
            record = session.scalar(select(ApiKeyRecord).where(ApiKeyRecord.name == name))
            if record is None:
                return False
            record.active = False
            return True

    def list_api_keys(self) -> list[dict[str, Any]]:
        with self.session() as session:
            return [
                {
                    "name": r.name,
                    "scopes": sorted(r.scope_set()),
                    "active": r.active,
                    "created_at": ensure_utc(r.created_at) if r.created_at else None,
                    "last_used_at": ensure_utc(r.last_used_at) if r.last_used_at else None,
                }
                for r in session.scalars(select(ApiKeyRecord)).all()
            ]

    def close(self) -> None:
        self.engine.dispose()


__all__ = [
    "ApiKeyRecord",
    "Base",
    "IngestCheckpoint",
    "JobRun",
    "MetadataStore",
]
