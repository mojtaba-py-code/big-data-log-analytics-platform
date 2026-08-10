"""Caching layer.

Key strategy
------------
``<namespace>:<prefix>:<blake2b-96 of the arguments>``

* ``namespace`` isolates deployments sharing one Redis.
* ``prefix`` names the *view* (``analytics.errors``, ``reports.daily``) so an
  operator can invalidate one family without flushing everything.
* The hash covers every argument that changes the answer — including the time
  range — so two different queries can never collide.

Invalidation
------------
Analytics data is append-only, so entries expire rather than being invalidated
by writes; TTL is the primary mechanism.  :func:`invalidate_after_ingest` is
called at the end of a pipeline run to drop cached aggregates that new data
would change, which keeps a dashboard from showing stale numbers after an
ingest even inside the TTL window.

What is *not* cached
--------------------
Anything derived from a specific user's identity or an unbounded-cardinality
parameter.  The API only caches views whose prefix appears in
``cache.cacheable_prefixes``.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, ParamSpec, TypeVar, cast

from app.cache.backends import (
    CacheBackend,
    CacheStats,
    MemoryCache,
    RedisCache,
    build_cache,
    cache_registry,
)
from app.core.logging import get_logger

log = get_logger(__name__)

P = ParamSpec("P")
T = TypeVar("T")

#: Cache prefixes that are dropped when new data lands.
INGEST_SENSITIVE_PREFIXES: tuple[str, ...] = (
    "analytics",
    "reports",
    "stats",
    "search",
    "anomalies",
    "security",
)


def cached(
    cache: CacheBackend, prefix: str, ttl: int | None = None
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Memoise a function's result in ``cache``.

    Arguments must be hashable-to-string; the key is derived from their
    ``str`` forms, which is why callers pass primitives (timestamps, names)
    rather than objects with identity-based ``repr``.
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            key = cache.build_key(
                prefix,
                func.__qualname__,
                *args,
                *(f"{k}={v}" for k, v in sorted(kwargs.items())),
            )
            hit = cache.get(key)
            if hit is not None:
                return cast("T", hit)
            value = func(*args, **kwargs)
            cache.set(key, value, ttl)
            return value

        return wrapper

    return decorator


def invalidate_after_ingest(cache: CacheBackend) -> int:
    """Drop cached aggregates that newly ingested data would change."""
    removed = sum(cache.clear(prefix) for prefix in INGEST_SENSITIVE_PREFIXES)
    if removed:
        log.info("cache invalidated after ingest", extra={"entries": removed})
    return removed


def cache_key_for_range(prefix: str, cache: CacheBackend, **params: Any) -> str:
    """Build a cache key from a view's parameters, in a stable order."""
    return cache.build_key(prefix, *(f"{k}={params[k]}" for k in sorted(params)))


__all__ = [
    "INGEST_SENSITIVE_PREFIXES",
    "CacheBackend",
    "CacheStats",
    "MemoryCache",
    "RedisCache",
    "build_cache",
    "cache_key_for_range",
    "cache_registry",
    "cached",
    "invalidate_after_ingest",
]
