"""API authentication, authorisation, rate limiting and security headers.

Authentication
--------------
API keys presented as ``X-API-Key`` or ``Authorization: Bearer <key>``.
Keys are compared with :func:`hmac.compare_digest` against **hashes** — the
plaintext is never stored, and comparison is constant-time so the response
latency cannot be used to recover a key byte by byte.

Two sources of keys, both supported at once:

* ``api.api_keys`` / ``api.api_key_hashes`` in configuration — simple
  deployments, keys managed as secrets.
* The metadata store — keys with names, scopes and revocation, minted by
  ``loganalytics apikey create``.

Authorisation
-------------
Scopes: ``read`` (query), ``write`` (trigger ingestion and jobs), ``admin``
(configuration, key management).  ``admin`` implies the others.  A route
declares what it needs; there is no implicit privilege.

Rate limiting
-------------
Token bucket per credential (falling back to client IP for unauthenticated
routes).  A bucket refills continuously rather than resetting on a fixed
window, which avoids the boundary burst that fixed windows allow.  State is
in-process by default; with Redis configured it is shared across replicas, so
the limit means the same thing behind a load balancer.

The client IP is taken from the socket, **not** from ``X-Forwarded-For``,
unless a trusted proxy is configured — otherwise any client can spoof its own
identity and bypass the limit entirely.
"""

from __future__ import annotations

import contextlib
import hmac
import ipaddress
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Annotated, Any, Final

from fastapi import Depends, Header, HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response
from starlette.types import ASGIApp

from app.core.config import Settings, get_settings
from app.core.hashing import hash_secret
from app.core.logging import get_logger

log = get_logger(__name__)

#: Signature of the ``call_next`` callable Starlette hands to middleware.
DispatchNext = RequestResponseEndpoint

SCOPE_READ: Final[str] = "read"
SCOPE_WRITE: Final[str] = "write"
SCOPE_ADMIN: Final[str] = "admin"

#: ``admin`` grants everything; ``write`` implies ``read``.
_SCOPE_IMPLIES: Final[dict[str, frozenset[str]]] = {
    SCOPE_ADMIN: frozenset({SCOPE_ADMIN, SCOPE_WRITE, SCOPE_READ}),
    SCOPE_WRITE: frozenset({SCOPE_WRITE, SCOPE_READ}),
    SCOPE_READ: frozenset({SCOPE_READ}),
}


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller."""

    name: str
    scopes: frozenset[str]
    source: str = "config"

    def has(self, scope: str) -> bool:
        return any(scope in _SCOPE_IMPLIES.get(held, frozenset()) for held in self.scopes)

    @property
    def is_anonymous(self) -> bool:
        return self.name == "anonymous"


#: The caller when ``api.auth_required`` is false.  It holds *every* scope on
#: purpose: with authentication disabled there is no way to obtain a higher
#: privilege, so a read-only anonymous principal would make writes impossible
#: rather than merely unauthenticated.  Production configuration validation
#: refuses ``auth_required=False``, so this can only ever apply in development.
ANONYMOUS = Principal(name="anonymous", scopes=frozenset({SCOPE_ADMIN}), source="anonymous")


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
def _configured_hashes(settings: Settings) -> list[str]:
    """Every acceptable key hash from configuration."""
    hashes = [h.strip().lower().removeprefix("sha256:") for h in settings.api.api_key_hashes]
    hashes += [hash_secret(key.get_secret_value()) for key in settings.api.api_keys]
    return [h for h in hashes if h]


def _extract_key(api_key_header: str | None, authorization: str | None) -> str | None:
    if api_key_header:
        return api_key_header.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def authenticate(
    request: Request,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    authorization: Annotated[str | None, Header()] = None,
    settings: Annotated[Settings, Depends(get_settings)] = None,  # type: ignore[assignment]
) -> Principal:
    """Resolve the caller, or raise 401.

    When ``api.auth_required`` is false (development only — production config
    validation rejects it) every caller is an anonymous reader.
    """
    config = settings or get_settings()
    if not config.api.auth_required:
        return ANONYMOUS

    presented = _extract_key(x_api_key, authorization)
    if not presented:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="an API key is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    presented_hash = hash_secret(presented)
    for known in _configured_hashes(config):
        if hmac.compare_digest(presented_hash, known):
            # Config keys are full-privilege by design: they are deployment
            # secrets, not per-user credentials.
            return Principal(name="config-key", scopes=frozenset({SCOPE_ADMIN}))

    principal = _authenticate_via_store(presented, config)
    if principal is not None:
        return principal

    # Log the attempt without the key: recording the credential someone tried
    # is how a log file becomes a credential store.
    log.warning(
        "authentication failed",
        extra={"client": client_identity(request, config), "path": request.url.path},
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid API key",
        headers={"WWW-Authenticate": "Bearer"},
    )


#: How long a verified principal is reused before the store is consulted again.
#: Revocation therefore takes effect within this window rather than instantly —
#: the trade for not paying a database round trip on every single request.
#: ``POST /admin/reload`` clears it immediately when that matters.
PRINCIPAL_CACHE_TTL_SECONDS: Final[float] = 30.0
_PRINCIPAL_CACHE_MAX = 1_024

_principal_cache: OrderedDict[str, tuple[float, Principal]] = OrderedDict()
_metadata_stores: dict[str, Any] = {}
_store_lock = threading.Lock()


def clear_principal_cache() -> None:
    """Drop cached principals — called on configuration reload and by tests."""
    with _store_lock:
        _principal_cache.clear()
        for store in _metadata_stores.values():
            with contextlib.suppress(Exception):
                store.close()
        _metadata_stores.clear()


def _metadata_store(settings: Settings) -> Any:
    """One store (and one connection pool) per database, not per request."""
    from app.storage import MetadataStore

    url = settings.database.url()
    store = _metadata_stores.get(url)
    if store is None:
        with _store_lock:
            store = _metadata_stores.get(url)
            if store is None:
                store = MetadataStore.from_settings(settings)
                _metadata_stores[url] = store
    return store


def _authenticate_via_store(presented: str, settings: Settings) -> Principal | None:
    cache_key = hash_secret(presented)
    now = time.monotonic()
    cached = _principal_cache.get(cache_key)
    if cached is not None:
        expires_at, principal = cached
        if expires_at > now:
            return principal
        _principal_cache.pop(cache_key, None)

    try:
        record = _metadata_store(settings).verify_api_key(presented)
    except Exception:  # noqa: BLE001 - metadata outage must not 500 every request
        log.warning("could not verify the API key against the metadata store")
        return None
    if record is None:
        # Failures are deliberately not cached: an attacker would otherwise get
        # a cheap oracle, and a newly created key would be rejected for 30 s.
        return None

    principal = Principal(name=record.name, scopes=frozenset(record.scope_set()), source="database")
    _principal_cache[cache_key] = (now + PRINCIPAL_CACHE_TTL_SECONDS, principal)
    while len(_principal_cache) > _PRINCIPAL_CACHE_MAX:
        _principal_cache.popitem(last=False)
    return principal


def require_scope(scope: str) -> Any:
    """Dependency factory: ``Depends(require_scope("write"))``."""

    def dependency(principal: Annotated[Principal, Depends(authenticate)]) -> Principal:
        if not principal.has(scope):
            log.warning(
                "authorisation denied",
                extra={"principal": principal.name, "required_scope": scope},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"this operation requires the '{scope}' scope",
            )
        return principal

    return dependency


RequireRead = Depends(require_scope(SCOPE_READ))
RequireWrite = Depends(require_scope(SCOPE_WRITE))
RequireAdmin = Depends(require_scope(SCOPE_ADMIN))


# --------------------------------------------------------------------------- #
# Client identity
# --------------------------------------------------------------------------- #
def client_identity(request: Request, settings: Settings) -> str:
    """Best available identifier for rate limiting and audit logs.

    ``X-Forwarded-For`` is only honoured when the *immediate* peer is a
    configured trusted proxy.  Trusting it unconditionally lets any client
    claim any identity, which defeats rate limiting and poisons audit trails.
    """
    peer = request.client.host if request.client else "unknown"
    trusted = getattr(settings.api, "trusted_proxies", ())
    if trusted and _address_in(peer, trusted):
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    return peer


def _address_in(address: str, networks: tuple[str, ...]) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    for network in networks:
        try:
            if ip in ipaddress.ip_network(network, strict=False):
                return True
        except ValueError:
            continue
    return False


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated_at: float


@dataclass
class TokenBucketLimiter:
    """Continuous-refill token bucket, keyed by caller identity."""

    rate_per_second: float
    capacity: float
    max_keys: int = 10_000
    _buckets: OrderedDict[str, _Bucket] = field(default_factory=OrderedDict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @classmethod
    def from_settings(cls, settings: Settings) -> TokenBucketLimiter:
        api = settings.api
        rate = api.rate_limit_requests / max(api.rate_limit_window_seconds, 1)
        return cls(
            rate_per_second=rate,
            capacity=float(api.rate_limit_requests + api.rate_limit_burst),
        )

    def check(self, key: str, cost: float = 1.0) -> tuple[bool, float, int]:
        """Return ``(allowed, retry_after_seconds, remaining_tokens)``."""
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self.capacity, updated_at=now)
                self._buckets[key] = bucket
                self._evict()
            else:
                elapsed = now - bucket.updated_at
                bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.rate_per_second)
                bucket.updated_at = now
                self._buckets.move_to_end(key)

            if bucket.tokens >= cost:
                bucket.tokens -= cost
                return True, 0.0, int(bucket.tokens)
            deficit = cost - bucket.tokens
            retry_after = deficit / self.rate_per_second if self.rate_per_second else 60.0
            return False, retry_after, 0

    def _evict(self) -> None:
        while len(self._buckets) > self.max_keys:
            self._buckets.popitem(last=False)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Applies the token bucket and sets the standard rate-limit headers."""

    #: Never rate-limit liveness probes: doing so takes the service out of the
    #: load balancer precisely when it is already under pressure.
    EXEMPT_PATHS: Final[frozenset[str]] = frozenset(
        {"/health", "/health/live", "/health/ready", "/metrics"}
    )

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        super().__init__(app)
        self.settings = settings
        self.limiter = TokenBucketLimiter.from_settings(settings)

    async def dispatch(self, request: Request, call_next: DispatchNext) -> Response:
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        key = _rate_limit_key(request, self.settings)
        allowed, retry_after, remaining = self.limiter.check(key)
        if not allowed:
            log.warning(
                "rate limit exceeded",
                extra={"client": key, "path": request.url.path},
            )
            from fastapi.responses import JSONResponse

            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"error": {"code": "rate_limited", "message": "Rate limit exceeded."}},
                headers={
                    "Retry-After": str(max(1, int(retry_after) + 1)),
                    "X-RateLimit-Limit": str(self.settings.api.rate_limit_requests),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.settings.api.rate_limit_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response


def _rate_limit_key(request: Request, settings: Settings) -> str:
    """Prefer the credential over the address: one key, one budget."""
    presented = _extract_key(request.headers.get("x-api-key"), request.headers.get("authorization"))
    if presented:
        return f"key:{hash_secret(presented)[:16]}"
    return f"ip:{client_identity(request, settings)}"


# --------------------------------------------------------------------------- #
# Security headers
# --------------------------------------------------------------------------- #
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds defensive response headers.

    The dashboard is served from this same origin, so the CSP allows inline
    styles and scripts for it — everything else (external hosts, framing,
    plugins) is denied.  ``connect-src 'self'`` means a compromised dashboard
    script cannot exfiltrate query results to another origin.
    """

    CSP: Final[str] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    def __init__(self, app: ASGIApp, *, hsts: bool = False) -> None:
        super().__init__(app)
        self.hsts = hsts

    async def dispatch(self, request: Request, call_next: DispatchNext) -> Response:
        response = await call_next(request)
        headers = response.headers
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault("Content-Security-Policy", self.CSP)
        headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        headers.setdefault("Cache-Control", "no-store")
        if "server" in headers:
            del headers["server"]  # do not advertise the stack
        if self.hsts:
            headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects oversized request bodies before they are buffered."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next: DispatchNext) -> Response:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            from fastapi.responses import JSONResponse

            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={
                    "error": {
                        "code": "payload_too_large",
                        "message": "The request body is too large.",
                    }
                },
            )
        return await call_next(request)


__all__ = [
    "ANONYMOUS",
    "PRINCIPAL_CACHE_TTL_SECONDS",
    "SCOPE_ADMIN",
    "SCOPE_READ",
    "SCOPE_WRITE",
    "Principal",
    "RateLimitMiddleware",
    "RequestSizeLimitMiddleware",
    "RequireAdmin",
    "RequireRead",
    "RequireWrite",
    "SecurityHeadersMiddleware",
    "TokenBucketLimiter",
    "authenticate",
    "clear_principal_cache",
    "client_identity",
    "require_scope",
]
