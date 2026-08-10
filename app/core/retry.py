"""Retry with exponential backoff and full jitter.

Used for every *transient* boundary: object storage, Redis, PostgreSQL, remote
HTTP ingestion.  Never used for per-record parse errors — those are
deterministic and belong in the dead-letter queue, not in a retry loop.

Why full jitter
---------------
Fixed backoff synchronises a fleet of workers into a thundering herd after an
outage.  ``random.uniform(0, backoff)`` spreads the retries out; it is the
variant AWS measured as best in practice.  ``random`` (not ``secrets``) is
correct here — this is load-spreading, not a security decision.
"""

from __future__ import annotations

import asyncio
import functools
import random
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, ParamSpec, TypeVar

from app.core.exceptions import RetryExhaustedError
from app.core.logging import get_logger

log = get_logger(__name__)

P = ParamSpec("P")
T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Declarative retry configuration."""

    attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 30.0
    multiplier: float = 2.0
    jitter: bool = True
    retry_on: tuple[type[BaseException], ...] = (OSError, TimeoutError, ConnectionError)

    def __post_init__(self) -> None:
        if self.attempts < 1:
            raise ValueError("attempts must be >= 1")
        if self.base_delay <= 0 or self.max_delay <= 0:
            raise ValueError("delays must be positive")

    def delay_for(self, attempt: int) -> float:
        """Delay before ``attempt`` (1-based); capped and optionally jittered."""
        raw = min(self.base_delay * (self.multiplier ** (attempt - 1)), self.max_delay)
        if not self.jitter:
            return raw
        return random.uniform(0.0, raw)  # noqa: S311 - load spreading, not crypto  # nosec B311

    def should_retry(self, exc: BaseException) -> bool:
        return isinstance(exc, self.retry_on)


DEFAULT_POLICY = RetryPolicy()


def call_with_retry(
    func: Callable[[], T],
    policy: RetryPolicy = DEFAULT_POLICY,
    *,
    description: str = "operation",
    on_retry: Callable[[int, BaseException, float], None] | None = None,
) -> T:
    """Invoke ``func`` under ``policy``; raise :class:`RetryExhaustedError` last."""
    last: BaseException | None = None
    for attempt in range(1, policy.attempts + 1):
        try:
            return func()
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            if not policy.should_retry(exc) or attempt == policy.attempts:
                if not policy.should_retry(exc):
                    raise
                last = exc
                break
            last = exc
            delay = policy.delay_for(attempt)
            log.warning(
                "%s failed, retrying",
                description,
                extra={
                    "attempt": attempt,
                    "max_attempts": policy.attempts,
                    "delay": round(delay, 3),
                    "error_type": type(exc).__name__,
                },
            )
            if on_retry is not None:
                on_retry(attempt, exc, delay)
            time.sleep(delay)
    raise RetryExhaustedError(
        f"{description} failed after {policy.attempts} attempts",
        attempts=policy.attempts,
        error_type=type(last).__name__ if last else None,
    ) from last


async def call_with_retry_async(
    func: Callable[[], Awaitable[T]],
    policy: RetryPolicy = DEFAULT_POLICY,
    *,
    description: str = "operation",
) -> T:
    """Async twin of :func:`call_with_retry`."""
    last: BaseException | None = None
    for attempt in range(1, policy.attempts + 1):
        try:
            return await func()
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            if not policy.should_retry(exc):
                raise
            last = exc
            if attempt == policy.attempts:
                break
            delay = policy.delay_for(attempt)
            log.warning(
                "%s failed, retrying",
                description,
                extra={"attempt": attempt, "delay": round(delay, 3)},
            )
            await asyncio.sleep(delay)
    raise RetryExhaustedError(
        f"{description} failed after {policy.attempts} attempts", attempts=policy.attempts
    ) from last


def retry(
    attempts: int = 3,
    *,
    base_delay: float = 0.5,
    max_delay: float = 30.0,
    retry_on: Sequence[type[BaseException]] = (OSError, TimeoutError, ConnectionError),
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Decorator form of :func:`call_with_retry`."""
    policy = RetryPolicy(
        attempts=attempts,
        base_delay=base_delay,
        max_delay=max_delay,
        retry_on=tuple(retry_on),
    )

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            return call_with_retry(
                lambda: func(*args, **kwargs), policy, description=func.__qualname__
            )

        return wrapper

    return decorator


class CircuitBreaker:
    """Trips after repeated failures so a dead dependency is not hammered.

    States: ``closed`` (normal) → ``open`` (fail fast) → ``half_open`` (one
    probe).  Keeps the platform responsive when Redis or PostgreSQL is down
    instead of stalling every request on a connection timeout.
    """

    __slots__ = ("_failures", "_opened_at", "_state", "failure_threshold", "reset_timeout")

    def __init__(self, failure_threshold: int = 5, reset_timeout: float = 30.0) -> None:
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._failures = 0
        self._opened_at = 0.0
        self._state = "closed"

    @property
    def state(self) -> str:
        if self._state == "open" and time.monotonic() - self._opened_at >= self.reset_timeout:
            self._state = "half_open"
        return self._state

    def allows(self) -> bool:
        return self.state != "open"

    def record_success(self) -> None:
        self._failures = 0
        self._state = "closed"

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.failure_threshold:
            self._state = "open"
            self._opened_at = time.monotonic()

    def call(self, func: Callable[[], T]) -> T:
        if not self.allows():
            raise RetryExhaustedError("circuit breaker is open", state=self._state)
        try:
            result = func()
        except Exception:
            self.record_failure()
            raise
        self.record_success()
        return result

    def snapshot(self) -> dict[str, Any]:
        return {"state": self.state, "failures": self._failures}


__all__ = [
    "DEFAULT_POLICY",
    "CircuitBreaker",
    "RetryPolicy",
    "call_with_retry",
    "call_with_retry_async",
    "retry",
]
