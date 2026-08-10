"""Cache backends.

Responsibility
--------------
Make repeated analytics queries cheap.  A dashboard polling ``/analytics/errors``
every 10 seconds must not re-scan Parquet every 10 seconds.

Two backends behind one interface:

* :class:`MemoryCache` — bounded LRU with per-entry TTL.  Zero dependencies,
  correct for a single process (CLI, tests, single-worker API).
* :class:`RedisCache` — shared across API replicas and workers, so a warm entry
  written by one process serves all of them.

Failure policy: **the cache is never load-bearing**.  Every Redis operation is
wrapped so that an outage degrades to a cache miss rather than an error page.
A circuit breaker stops hammering a dead Redis on every request.

Security
--------
* Keys are namespaced and hashed, so a cached key cannot be guessed from a URL
  and cannot collide across tenants or query shapes.
* Values are JSON, never pickle.  Unpickling data from a shared cache is remote
  code execution if anything can write to Redis.
* The API layer decides *what* may be cached (see
  ``cache.cacheable_prefixes``); per-user data must never share a key.
"""

from __future__ import annotations

import json
import threading
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar, cast

from app.core.config import CacheSettings
from app.core.hashing import content_hash
from app.core.logging import get_logger
from app.core.registry import Registry
from app.core.retry import CircuitBreaker

log = get_logger(__name__)

T = TypeVar("T")

cache_registry: Registry[CacheBackend] = Registry("cache backend")


@dataclass(slots=True)
class CacheStats:
    hits: int = 0
    misses: int = 0
    sets: int = 0
    errors: int = 0
    evictions: int = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total else 0.0

    def as_dict(self) -> dict[str, float | int]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "sets": self.sets,
            "errors": self.errors,
            "evictions": self.evictions,
            "hit_rate": round(self.hit_rate, 4),
        }


class CacheBackend(ABC):
    """Minimal cache interface: get, set, delete, clear-by-prefix."""

    name = "base"

    def __init__(self, namespace: str = "loga", default_ttl: int = 300) -> None:
        self.namespace = namespace
        self.default_ttl = default_ttl
        self.stats = CacheStats()

    # -- key construction ---------------------------------------------------- #
    def build_key(self, prefix: str, *parts: Any) -> str:
        """Namespaced, hashed key.

        The readable prefix keeps ``redis-cli --scan`` useful for operators,
        while the hashed tail keeps keys short and free of user-controlled text
        (a raw search string in a key is both unbounded and a leak).
        """
        digest = content_hash("|".join(str(part) for part in parts), digest_size=12)
        return f"{self.namespace}:{prefix}:{digest}"

    @abstractmethod
    def get(self, key: str) -> Any | None: ...

    @abstractmethod
    def set(self, key: str, value: Any, ttl: int | None = None) -> None: ...

    @abstractmethod
    def delete(self, key: str) -> None: ...

    @abstractmethod
    def clear(self, prefix: str | None = None) -> int:
        """Invalidate everything, or everything under ``prefix``."""

    def get_or_set(self, key: str, factory: Callable[[], T], ttl: int | None = None) -> T:
        """Return the cached value or compute, store and return it."""
        cached = self.get(key)
        if cached is not None:
            return cast("T", cached)
        value = factory()
        self.set(key, value, ttl)
        return value

    def health(self) -> dict[str, Any]:
        return {"backend": self.name, "healthy": True, **self.stats.as_dict()}

    def close(self) -> None:  # noqa: B027 - optional hook; memory has nothing to close
        """Release resources."""


@cache_registry.register("memory", "local", "inmemory")
class MemoryCache(CacheBackend):
    """Bounded LRU with per-entry expiry.

    Bounded because an unbounded process-local cache is just a slow memory
    leak: an analytics API with a date-range parameter has effectively infinite
    distinct keys.
    """

    name = "memory"

    def __init__(
        self, namespace: str = "loga", default_ttl: int = 300, max_entries: int = 10_000
    ) -> None:
        super().__init__(namespace, default_ttl)
        self.max_entries = max(16, max_entries)
        self._entries: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = threading.RLock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self.stats.misses += 1
                return None
            expires_at, value = entry
            # ``<=``, not ``<``: with a zero TTL the deadline equals the write
            # time, and on a coarse clock (Windows, ~15 ms) a strict comparison
            # would serve an entry that was asked to expire immediately.
            if expires_at <= time.monotonic():
                del self._entries[key]
                self.stats.misses += 1
                return None
            self._entries.move_to_end(key)
            self.stats.hits += 1
            return value

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        with self._lock:
            # ``ttl=0`` means "expire immediately"; only ``None`` means
            # "use the default".  Treating 0 as falsy would silently cache an
            # entry the caller explicitly asked not to keep.
            lifetime = self.default_ttl if ttl is None else ttl
            self._entries[key] = (time.monotonic() + lifetime, value)
            self._entries.move_to_end(key)
            self.stats.sets += 1
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
                self.stats.evictions += 1

    def delete(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def clear(self, prefix: str | None = None) -> int:
        with self._lock:
            if prefix is None:
                count = len(self._entries)
                self._entries.clear()
                return count
            needle = f"{self.namespace}:{prefix}"
            doomed = [key for key in self._entries if key.startswith(needle)]
            for key in doomed:
                del self._entries[key]
            return len(doomed)

    def __len__(self) -> int:
        return len(self._entries)


@cache_registry.register("redis")
class RedisCache(CacheBackend):
    """Redis-backed cache with JSON values and fail-open semantics."""

    name = "redis"

    def __init__(
        self,
        url: str,
        namespace: str = "loga",
        default_ttl: int = 300,
        *,
        client: Any | None = None,
        socket_timeout: float = 1.0,
    ) -> None:
        super().__init__(namespace, default_ttl)
        self.url = url
        self._breaker = CircuitBreaker(failure_threshold=3, reset_timeout=15.0)
        if client is not None:
            self._client = client
            return
        try:
            import redis

            self._client = redis.Redis.from_url(
                url,
                decode_responses=True,
                socket_timeout=socket_timeout,
                socket_connect_timeout=socket_timeout,
                health_check_interval=30,
            )
        except ImportError as exc:  # pragma: no cover - declared dependency
            raise RuntimeError("redis is required for the redis cache backend") from exc

    def _guard(self, operation: str, action: Callable[[], T], default: T) -> T:
        """Run a Redis call, degrading to ``default`` on any failure."""
        if not self._breaker.allows():
            return default
        try:
            result = action()
        except Exception as exc:  # noqa: BLE001 - any redis failure is a miss
            self._breaker.record_failure()
            self.stats.errors += 1
            log.warning(
                "cache operation failed; continuing without cache",
                extra={"operation": operation, "error_type": type(exc).__name__},
            )
            return default
        self._breaker.record_success()
        return result

    def get(self, key: str) -> Any | None:
        raw = self._guard("get", lambda: self._client.get(key), None)
        if raw is None:
            self.stats.misses += 1
            return None
        try:
            value = json.loads(raw)
        except ValueError:
            # A corrupt entry is a miss, not an error: drop it and move on.
            self.delete(key)
            self.stats.misses += 1
            return None
        self.stats.hits += 1
        return value

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        try:
            payload = json.dumps(value, default=str)
        except (TypeError, ValueError):
            log.warning("value is not JSON-serialisable; not cached")
            return
        # ``set(..., ex=)`` rather than ``setex``: the latter is deprecated in
        # redis-py 5+, and Redis rejects a zero expiry, so it is clamped.
        lifetime = max(1, self.default_ttl if ttl is None else ttl)
        self._guard("set", lambda: self._client.set(key, payload, ex=lifetime), None)
        self.stats.sets += 1

    def delete(self, key: str) -> None:
        self._guard("delete", lambda: self._client.delete(key), None)

    def clear(self, prefix: str | None = None) -> int:
        pattern = f"{self.namespace}:{prefix}:*" if prefix else f"{self.namespace}:*"

        def _scan_delete() -> int:
            removed = 0
            # SCAN, never KEYS: KEYS blocks the whole server on a large keyspace.
            for key in self._client.scan_iter(match=pattern, count=500):
                self._client.delete(key)
                removed += 1
            return removed

        return self._guard("clear", _scan_delete, 0)

    def health(self) -> dict[str, Any]:
        healthy = self._guard("ping", lambda: bool(self._client.ping()), False)
        return {
            "backend": self.name,
            "healthy": healthy,
            "circuit": self._breaker.snapshot(),
            **self.stats.as_dict(),
        }

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:  # noqa: BLE001 - best effort on shutdown
            log.debug("redis client close failed")


def build_cache(settings: CacheSettings) -> CacheBackend:
    """Instantiate the configured backend, falling back to memory on failure.

    Falling back is deliberate: an unreachable Redis at boot should degrade
    performance, not prevent the service from starting.
    """
    if settings.backend == "redis":
        try:
            cache = RedisCache(
                settings.redis_url(),
                namespace=settings.namespace,
                default_ttl=settings.default_ttl_seconds,
            )
            if cache.health()["healthy"]:
                return cache
            log.warning("redis is unreachable; using the in-memory cache instead")
        except Exception as exc:  # noqa: BLE001 - never block startup on cache
            log.warning(
                "failed to initialise redis cache; using memory",
                extra={"error_type": type(exc).__name__},
            )
    return MemoryCache(
        namespace=settings.namespace,
        default_ttl=settings.default_ttl_seconds,
        max_entries=settings.max_entries,
    )


__all__ = [
    "CacheBackend",
    "CacheStats",
    "MemoryCache",
    "RedisCache",
    "build_cache",
    "cache_registry",
]
