"""Shared pytest fixtures.

Every fixture that touches the filesystem uses ``tmp_path``, and every
:class:`~app.core.config.Settings` is built explicitly rather than read from the
environment — a test that depends on the developer's ``.env`` is a test that
fails in CI for reasons nobody can reproduce.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.core.config import Settings, load_settings, reset_settings_cache
from app.core.timeutil import utcnow
from app.models.enums import LogLevel
from app.models.log_event import LogEvent


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Strip platform env vars and caches so tests cannot leak into each other."""
    import os

    for key in [k for k in os.environ if k.startswith("LOGA_")]:
        monkeypatch.delenv(key, raising=False)
    reset_settings_cache()
    yield
    reset_settings_cache()


@pytest.fixture
def data_root(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    (root / "raw").mkdir(parents=True)
    return root


@pytest.fixture
def settings(tmp_path: Path, data_root: Path) -> Settings:
    """A fully isolated configuration pointing at a temporary data root."""
    return load_settings(
        overrides={
            "environment": "test",
            "storage": {"data_root": str(data_root), "write_batch_size": 1_000},
            "ingestion": {"allowed_roots": [str(tmp_path)]},
            "processing": {"batch_size": 500, "workers": 1},
            "database": {"sqlite_path": str(tmp_path / "metadata.db")},
            "api": {"auth_required": False, "docs_enabled": True},
            "observability": {"level": "WARNING", "format": "console"},
            "cache": {"backend": "memory"},
        }
    )


@pytest.fixture
def base_time() -> datetime:
    """Anchor for every generated record: a whole hour, six hours ago.

    Relative to *now*, not a fixed date.  A fixed date silently rots: search
    and analytics default to a rolling 24-hour window, so fixture data pinned
    to a calendar date slides out of that window as the clock advances and
    counts start drifting days after the test was written.  Anchoring to the
    current hour keeps the data inside the default window forever while still
    giving every record a deterministic offset.
    """
    return utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(hours=6)


@pytest.fixture
def sample_event(base_time: datetime) -> LogEvent:
    return LogEvent.build(
        timestamp=base_time,
        level=LogLevel.ERROR,
        service="payment",
        hostname="host-01",
        message="database connection failed",
        ip_address="192.0.2.10",
        http_method="POST",
        endpoint="/api/v1/payments",
        status_code=500,
        response_time_ms=250.5,
        bytes_sent=512,
        user_agent="curl/8.5.0",
        request_id="abc123",
        source="test",
    )


@pytest.fixture
def sample_events(base_time: datetime) -> list[LogEvent]:
    """A deterministic mixed dataset: 200 records, ~25 % errors, 4 services."""
    services = ("api", "auth", "payment", "search")
    events: list[LogEvent] = []
    for index in range(200):
        is_error = index % 4 == 0
        events.append(
            LogEvent.build(
                timestamp=base_time + timedelta(seconds=index * 30),
                level=LogLevel.ERROR if is_error else LogLevel.INFO,
                service=services[index % len(services)],
                hostname=f"host-{index % 3:02d}",
                message=f"request {index}",
                ip_address=f"192.0.2.{index % 50 + 1}",
                http_method="GET" if index % 2 else "POST",
                endpoint=f"/api/v1/resource/{index % 7}",
                status_code=500 if is_error else 200,
                response_time_ms=float(20 + (index % 40) * 5),
                bytes_sent=100 + index,
                source="test",
            )
        )
    return events


@pytest.fixture
def populated_store(settings: Settings, sample_events: list[LogEvent]) -> Path:
    """A Parquet dataset written to the processed layer."""
    from app.storage import ParquetStore

    store = ParquetStore(settings.processed_path, batch_size=1_000)
    store.write(sample_events, run_id="fixture")
    store.flush()
    return settings.processed_path


@pytest.fixture
def log_file(tmp_path: Path) -> Path:
    """A small JSON-lines log file on disk."""
    path = tmp_path / "raw" / "app.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        '{"timestamp":"2026-08-07T12:00:00Z","level":"INFO","service":"api",'
        '"message":"request completed","status":200,"duration_ms":12.5}',
        '{"timestamp":"2026-08-07T12:00:01Z","level":"ERROR","service":"api",'
        '"message":"database connection failed","status":500,"duration_ms":940.0}',
        '{"timestamp":"2026-08-07T12:00:02Z","level":"WARNING","service":"auth",'
        '"message":"authentication failed","status":401,"duration_ms":30.0}',
        "this line is not valid json at all",
        '{"timestamp":"2026-08-07T12:00:03Z","level":"INFO","service":"auth",'
        '"message":"token refreshed","status":200,"duration_ms":8.0}',
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def access_log_file(tmp_path: Path) -> Path:
    """An Apache/Nginx combined-format access log."""
    path = tmp_path / "raw" / "access.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        '192.0.2.1 - - [07/Aug/2026:12:00:00 +0000] "GET /api/v1/products HTTP/1.1" '
        '200 1043 "-" "Mozilla/5.0" 0.052',
        '192.0.2.2 - alice [07/Aug/2026:12:00:01 +0000] "POST /api/v1/orders HTTP/1.1" '
        '201 88 "https://example.test/" "Mozilla/5.0" 0.310',
        '198.51.100.7 - - [07/Aug/2026:12:00:02 +0000] "GET /.env HTTP/1.1" '
        '404 153 "-" "sqlmap/1.8" 0.001',
        '192.0.2.3 - - [07/Aug/2026:12:00:03 +0000] "GET /api/v1/search HTTP/1.1" '
        '500 512 "-" "curl/8.5.0" 1.204',
    ]
    path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def api_client(settings: Settings, populated_store: Path):  # noqa: ANN201 - TestClient
    """A FastAPI test client wired to the isolated settings."""
    from fastapi.testclient import TestClient

    from app.api.deps import reset_dependencies
    from app.api.main import create_app

    reset_dependencies()
    with TestClient(create_app(settings)) as client:
        yield client
    reset_dependencies()


@pytest.fixture
def authed_settings(tmp_path: Path, data_root: Path) -> Settings:
    """Settings with authentication switched on and one known key."""
    return load_settings(
        overrides={
            "environment": "test",
            "storage": {"data_root": str(data_root)},
            "ingestion": {"allowed_roots": [str(tmp_path)]},
            "database": {"sqlite_path": str(tmp_path / "metadata.db")},
            "api": {
                "auth_required": True,
                "api_keys": ["test-key-abcdefghijklmnop"],
                "rate_limit_requests": 1_000,
            },
            "observability": {"level": "ERROR", "format": "console"},
        }
    )
