"""Configuration layer.

Responsibility
--------------
Provide one immutable, validated, fully type-hinted view of *all* runtime
configuration, assembled from (in increasing precedence):

1. built-in defaults declared on the models below;
2. a YAML or JSON config file (``configs/default.yaml``);
3. environment variables / ``.env`` (prefix ``LOGA_``, nested via ``__``).

Security considerations
-----------------------
* Every credential is typed :class:`~pydantic.SecretStr`.  ``repr`` of the
  settings object therefore never leaks a password, and neither does a Pydantic
  validation error — which is exactly when configuration objects get dumped.
* Credentials have **no defaults**.  A missing password is an error, never an
  empty string that silently connects to an unprotected database.
* ``data_root`` and ``allowed_ingest_roots`` are resolved to absolute paths at
  load time and become the only directories the process is allowed to touch
  (enforced by :mod:`app.core.paths`).

Performance considerations
--------------------------
Settings are loaded once and cached (:func:`get_settings`).  Nothing on a hot
path re-reads the environment or the filesystem.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.exceptions import ConfigurationError
from app.core.masking import ALL_RULES, DEFAULT_RULES

ENV_PREFIX = "LOGA_"
CONFIG_PATH_ENV = "LOGA_CONFIG_FILE"


class _Section(BaseModel):
    """Base for configuration sections: frozen and strict about unknown keys."""

    model_config = {"frozen": True, "extra": "forbid"}


# --------------------------------------------------------------------------- #
# Sections
# --------------------------------------------------------------------------- #
class StorageSettings(_Section):
    """Where data lands and in which physical format."""

    data_root: Path = Path("data")
    raw_dir: str = "raw"
    processed_dir: str = "processed"
    analytics_dir: str = "analytics"
    rejected_dir: str = "rejected"
    format: Literal["parquet", "jsonl", "csv"] = "parquet"
    compression: Literal["zstd", "snappy", "gzip", "none"] = "zstd"
    #: Rows buffered in memory before a Parquet row-group is flushed.  Trades
    #: peak RSS against file count / compression ratio.
    write_batch_size: int = Field(default=50_000, ge=1_000, le=1_000_000)
    partition_by: tuple[str, ...] = ("year", "month", "day")

    @field_validator("data_root")
    @classmethod
    def _absolute(cls, value: Path) -> Path:
        return value.expanduser().resolve()


class ProcessingSettings(_Section):
    """Throughput / memory knobs for the batch pipeline."""

    batch_size: int = Field(default=10_000, ge=100, le=1_000_000)
    workers: int = Field(default=4, ge=1, le=64)
    #: Hard cap on a single log line.  Anything longer is dead-lettered instead
    #: of being buffered — this is the primary memory-exhaustion guard.
    max_line_bytes: int = Field(default=1_048_576, ge=1_024, le=64 * 1_048_576)
    max_file_bytes: int = Field(default=20 * 1024**3, ge=1024)
    #: Stop the job once this fraction of records has been rejected.
    error_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    #: Records to sample when auto-detecting a file's log format.
    format_sample_lines: int = Field(default=25, ge=1, le=1_000)
    encoding: str = "utf-8"
    #: ``replace`` keeps a mojibake line rather than aborting a 10 GB job.
    encoding_errors: Literal["strict", "replace", "ignore"] = "replace"


class DeduplicationSettings(_Section):
    strategy: Literal["none", "event_id", "content_hash", "fields"] = "content_hash"
    fields: tuple[str, ...] = ("timestamp", "service", "level", "message")
    #: Bounded LRU of seen fingerprints.  Beyond this, the oldest are evicted:
    #: duplicates separated by more than this many records may slip through.
    max_tracked_keys: int = Field(default=1_000_000, ge=1_000)
    #: Emit duplicates to the rejected store instead of dropping them.
    keep_duplicates: bool = False


class ValidationSettings(_Section):
    require_timestamp: bool = True
    require_message: bool = False
    #: Records further than this into the future are rejected as clock-skewed.
    max_future_skew_seconds: int = Field(default=300, ge=0)
    max_age_days: int = Field(default=3_650, ge=1)
    max_message_length: int = Field(default=32_768, ge=128)
    allowed_levels: tuple[str, ...] = (
        "TRACE",
        "DEBUG",
        "INFO",
        "NOTICE",
        "WARNING",
        "ERROR",
        "CRITICAL",
        "ALERT",
        "EMERGENCY",
        "UNKNOWN",
    )


class MaskingSettings(_Section):
    enabled: bool = True
    rules: tuple[str, ...] = DEFAULT_RULES
    extra_fields: tuple[str, ...] = ()
    #: Mask the verbatim source line too.  Costs one extra regex pass per
    #: record but is the only way to guarantee no secret is ever persisted.
    mask_raw_message: bool = True

    @field_validator("rules")
    @classmethod
    def _known_rules(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        unknown = sorted(set(value) - set(ALL_RULES))
        if unknown:
            raise ValueError(f"unknown masking rules {unknown}; known: {sorted(ALL_RULES)}")
        return value


class AnalyticsSettings(_Section):
    enable_anomaly_detection: bool = True
    default_window: Literal["1m", "5m", "15m", "1h", "6h", "1d"] = "5m"
    zscore_threshold: float = Field(default=3.0, gt=0)
    iqr_multiplier: float = Field(default=1.5, gt=0)
    moving_average_window: int = Field(default=12, ge=2, le=1_000)
    #: Minimum observations before a detector is allowed to flag anything.
    min_history_points: int = Field(default=10, ge=3)
    latency_percentiles: tuple[float, ...] = (0.5, 0.95, 0.99)
    #: Analytical query engine.  DuckDB streams from Parquet; Polars is faster
    #: on small in-memory frames.  See docs/PERFORMANCE.md.
    engine: Literal["duckdb", "polars"] = "duckdb"
    #: Cap on rows a single API query may return, before pagination.
    max_query_rows: int = Field(default=10_000, ge=1, le=1_000_000)
    query_timeout_seconds: float = Field(default=30.0, gt=0, le=600)


class SecurityAnalyticsSettings(_Section):
    enabled: bool = True
    failed_auth_threshold: int = Field(default=5, ge=1)
    failed_auth_window_seconds: int = Field(default=300, ge=1)
    not_found_threshold: int = Field(default=25, ge=1)
    request_rate_threshold: int = Field(default=300, ge=1)
    sensitive_endpoints: tuple[str, ...] = (
        "/admin",
        "/login",
        "/api/keys",
        "/.env",
        "/.git",
        "/wp-admin",
        "/actuator",
        "/phpmyadmin",
    )
    suspicious_user_agents: tuple[str, ...] = (
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "havij",
        "acunetix",
        "dirbuster",
        "gobuster",
        "wpscan",
        "curl/7.",
        "python-requests",
    )


class DatabaseSettings(_Section):
    """Transactional metadata store (job runs, checkpoints, API keys)."""

    driver: Literal["sqlite", "postgresql", "mysql"] = "sqlite"
    host: str = "localhost"
    port: int = Field(default=5432, ge=1, le=65535)
    name: str = "loganalytics"
    user: str = "loganalytics"
    password: SecretStr | None = None
    sqlite_path: Path = Path("data/metadata.db")
    pool_size: int = Field(default=5, ge=1, le=100)
    echo: bool = False

    def url(self) -> str:
        """Build a SQLAlchemy URL.  The password is only unwrapped here."""
        if self.driver == "sqlite":
            return f"sqlite:///{self.sqlite_path.as_posix()}"
        if self.password is None:
            raise ConfigurationError(
                "database password is required for non-sqlite drivers",
                driver=self.driver,
            )
        from urllib.parse import quote_plus

        secret = quote_plus(self.password.get_secret_value())
        user = quote_plus(self.user)
        scheme = "postgresql+psycopg2" if self.driver == "postgresql" else "mysql+pymysql"
        return f"{scheme}://{user}:{secret}@{self.host}:{self.port}/{self.name}"


class CacheSettings(_Section):
    backend: Literal["memory", "redis"] = "memory"
    redis_host: str = "localhost"
    redis_port: int = Field(default=6379, ge=1, le=65535)
    redis_db: int = Field(default=0, ge=0, le=15)
    redis_password: SecretStr | None = None
    redis_tls: bool = False
    namespace: str = "loga"
    default_ttl_seconds: int = Field(default=300, ge=1, le=86_400)
    max_entries: int = Field(default=10_000, ge=16)
    #: Never cache a response derived from these; belt-and-braces against a
    #: future endpoint caching per-user data under a shared key.
    cacheable_prefixes: tuple[str, ...] = ("analytics", "reports", "stats")

    def redis_url(self) -> str:
        scheme = "rediss" if self.redis_tls else "redis"
        auth = ""
        if self.redis_password is not None:
            from urllib.parse import quote_plus

            auth = f":{quote_plus(self.redis_password.get_secret_value())}@"
        return f"{scheme}://{auth}{self.redis_host}:{self.redis_port}/{self.redis_db}"


class ApiSettings(_Section):
    host: str = "127.0.0.1"  # loopback by default; opt in to 0.0.0.0 explicitly
    port: int = Field(default=8000, ge=1, le=65535)
    root_path: str = ""
    title: str = "Big Data Log Analytics Platform"
    docs_enabled: bool = True
    cors_origins: tuple[str, ...] = ()
    #: ``auth_required=False`` is only honoured when environment != production.
    auth_required: bool = True
    api_keys: tuple[SecretStr, ...] = ()
    #: Optional pre-hashed keys (``sha256:<hex>``) so plaintext never appears
    #: in config files at all.  Preferred for production.
    api_key_hashes: tuple[str, ...] = ()
    rate_limit_requests: int = Field(default=120, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)
    rate_limit_burst: int = Field(default=20, ge=0)
    max_page_size: int = Field(default=1_000, ge=1, le=10_000)
    default_page_size: int = Field(default=50, ge=1, le=10_000)
    request_timeout_seconds: float = Field(default=30.0, gt=0)
    max_request_bytes: int = Field(default=1_048_576, ge=1_024)
    enable_dashboard: bool = True
    #: CIDRs whose ``X-Forwarded-For`` header may be trusted.  Empty means the
    #: header is ignored entirely — the safe default, since a spoofable client
    #: identity defeats both rate limiting and audit logging.
    trusted_proxies: tuple[str, ...] = ()
    #: Send HSTS.  Only meaningful behind TLS; harmless but pointless on plain
    #: HTTP, and actively confusing during local development.
    hsts_enabled: bool = False

    @field_validator("cors_origins")
    @classmethod
    def _no_wildcard_with_credentials(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if "*" in value and len(value) > 1:
            raise ValueError("cors_origins cannot mix '*' with explicit origins")
        return value


class ObservabilitySettings(_Section):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: Literal["json", "console"] = "json"
    service_name: str = "log-analytics"
    file: Path | None = None
    max_file_bytes: int = Field(default=10 * 1024**2, ge=1024)
    backup_count: int = Field(default=5, ge=0, le=100)
    include_caller: bool = True
    #: Emit throughput/latency counters at the end of every pipeline run.
    metrics_enabled: bool = True


class WorkerSettings(_Section):
    backend: Literal["thread", "process", "celery"] = "thread"
    concurrency: int = Field(default=2, ge=1, le=64)
    queue_max_size: int = Field(default=1_000, ge=1)
    job_timeout_seconds: float = Field(default=3_600.0, gt=0)
    result_ttl_seconds: int = Field(default=86_400, ge=60)
    broker_url: str | None = None
    max_retries: int = Field(default=3, ge=0, le=10)
    retry_backoff_seconds: float = Field(default=1.0, gt=0)


class StreamingSettings(_Section):
    enabled: bool = False
    brokers: tuple[str, ...] = ("localhost:9092",)
    topic: str = "logs"
    group_id: str = "log-analytics"
    poll_timeout_seconds: float = Field(default=1.0, gt=0)
    max_batch: int = Field(default=1_000, ge=1)
    #: Flush the in-memory window to storage at least this often.
    flush_interval_seconds: float = Field(default=10.0, gt=0)


class IngestionSettings(_Section):
    #: Directories the platform may read source files from.  Empty means
    #: "``storage.data_root`` only".  Enforced by :mod:`app.core.paths`.
    allowed_roots: tuple[Path, ...] = ()
    follow_symlinks: bool = False
    #: Outbound HTTP ingestion is SSRF-sensitive; private ranges are blocked
    #: unless explicitly permitted here.
    allow_private_network_sources: bool = False
    http_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    http_max_bytes: int = Field(default=256 * 1024**2, ge=1024)
    db_fetch_size: int = Field(default=5_000, ge=1)

    @field_validator("allowed_roots")
    @classmethod
    def _absolute(cls, value: tuple[Path, ...]) -> tuple[Path, ...]:
        return tuple(p.expanduser().resolve() for p in value)


# --------------------------------------------------------------------------- #
# Root settings
# --------------------------------------------------------------------------- #
class Settings(BaseSettings):
    """Immutable root configuration object."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    environment: Literal["development", "staging", "production", "test"] = "development"
    debug: bool = False

    storage: StorageSettings = StorageSettings()
    processing: ProcessingSettings = ProcessingSettings()
    deduplication: DeduplicationSettings = DeduplicationSettings()
    validation: ValidationSettings = ValidationSettings()
    masking: MaskingSettings = MaskingSettings()
    analytics: AnalyticsSettings = AnalyticsSettings()
    security_analytics: SecurityAnalyticsSettings = SecurityAnalyticsSettings()
    database: DatabaseSettings = DatabaseSettings()
    cache: CacheSettings = CacheSettings()
    api: ApiSettings = ApiSettings()
    observability: ObservabilitySettings = ObservabilitySettings()
    workers: WorkerSettings = WorkerSettings()
    streaming: StreamingSettings = StreamingSettings()
    ingestion: IngestionSettings = IngestionSettings()

    # -- cross-section invariants ----------------------------------------- #
    @model_validator(mode="after")
    def _production_hardening(self) -> Settings:
        """Refuse configurations that are unsafe for production.

        These checks exist because the failure mode is silent: an API deployed
        with ``auth_required=False`` looks perfectly healthy while serving every
        log line to the internet.
        """
        if self.environment != "production":
            return self
        problems: list[str] = []
        if self.debug:
            problems.append("debug must be false in production")
        if not self.api.auth_required:
            problems.append("api.auth_required must be true in production")
        if self.api.auth_required and not (self.api.api_keys or self.api.api_key_hashes):
            problems.append("no API credentials configured while auth is required")
        if "*" in self.api.cors_origins:
            problems.append("api.cors_origins must not be '*' in production")
        if not self.masking.enabled:
            problems.append("masking.enabled must be true in production")
        if self.observability.level == "DEBUG":
            problems.append("observability.level DEBUG leaks payloads in production")
        if self.api.docs_enabled:
            problems.append("api.docs_enabled should be false in production")
        if problems:
            raise ValueError("; ".join(problems))
        return self

    # -- derived helpers --------------------------------------------------- #
    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def raw_path(self) -> Path:
        return self.storage.data_root / self.storage.raw_dir

    @property
    def processed_path(self) -> Path:
        return self.storage.data_root / self.storage.processed_dir

    @property
    def analytics_path(self) -> Path:
        return self.storage.data_root / self.storage.analytics_dir

    @property
    def rejected_path(self) -> Path:
        return self.storage.data_root / self.storage.rejected_dir

    def ingest_roots(self) -> tuple[Path, ...]:
        """Directories a source file is allowed to live under."""
        return self.ingestion.allowed_roots or (self.storage.data_root,)

    def safe_dump(self) -> dict[str, Any]:
        """Config dump with every secret redacted — safe to log or serve."""
        dumped: dict[str, Any] = json.loads(self.model_dump_json())
        return dumped


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def _read_config_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ConfigurationError("configuration file not found", path=str(path))
    text = path.read_text(encoding="utf-8")
    try:
        if path.suffix.lower() in {".yaml", ".yml"}:
            # safe_load never instantiates arbitrary Python objects.
            data = yaml.safe_load(text) or {}
        elif path.suffix.lower() == ".json":
            data = json.loads(text)
        else:
            raise ConfigurationError(
                "unsupported configuration format (use .yaml, .yml or .json)",
                path=str(path),
            )
    except (yaml.YAMLError, json.JSONDecodeError) as exc:
        raise ConfigurationError("configuration file is not valid", path=str(path)) from exc
    if not isinstance(data, Mapping):
        raise ConfigurationError("configuration root must be a mapping", path=str(path))
    return dict(data)


def load_settings(
    config_file: str | Path | None = None,
    overrides: Mapping[str, Any] | None = None,
) -> Settings:
    """Build a :class:`Settings` instance.

    Precedence (low → high): file → environment → ``overrides``.
    """
    file_data: dict[str, Any] = {}
    path = config_file or os.environ.get(CONFIG_PATH_ENV)
    if path:
        file_data = _read_config_file(Path(path).expanduser())
    payload: dict[str, Any] = {**file_data, **(dict(overrides) if overrides else {})}
    try:
        return Settings(**payload)
    except ConfigurationError:
        raise
    except Exception as exc:  # pydantic ValidationError and friends
        raise ConfigurationError(f"invalid configuration: {exc}") from exc


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide cached settings (the FastAPI/CLI dependency entry point)."""
    return load_settings()


def reset_settings_cache() -> None:
    """Drop the cache — used by tests and by ``loganalytics config reload``."""
    get_settings.cache_clear()


__all__ = [
    "AnalyticsSettings",
    "ApiSettings",
    "CacheSettings",
    "DatabaseSettings",
    "DeduplicationSettings",
    "IngestionSettings",
    "MaskingSettings",
    "ObservabilitySettings",
    "ProcessingSettings",
    "SecurityAnalyticsSettings",
    "Settings",
    "StorageSettings",
    "StreamingSettings",
    "ValidationSettings",
    "WorkerSettings",
    "get_settings",
    "load_settings",
    "reset_settings_cache",
]
