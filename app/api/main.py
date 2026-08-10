"""FastAPI application factory.

Middleware order matters and is deliberate (outermost first):

1. ``SecurityHeadersMiddleware`` — must wrap everything, including error
   responses generated deeper in the stack.
2. ``RequestSizeLimitMiddleware`` — reject oversized bodies before anything
   buffers them.
3. ``RequestContextMiddleware`` — assign the request id early so every log line
   and every error body carries it.
4. ``RateLimitMiddleware`` — after the request id (so throttles are traceable)
   but before routing (so a limited request costs nothing).
5. CORS, when configured.

The app is built by a **factory** rather than at import time: tests build one
per configuration, and importing the module must not open a DuckDB connection
or start worker threads.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.types import ASGIApp

from app import __version__
from app.api.errors import install_error_handlers
from app.api.routers import admin, analytics, health, jobs, logs, reports
from app.api.security import (
    DispatchNext,
    RateLimitMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from app.core.config import Settings, get_settings
from app.core.logging import configure_from_settings, get_logger, set_request_id
from app.core.metrics import global_metrics

log = get_logger(__name__)

DESCRIPTION = """
Query, analyse and report on very large log datasets.

**Authentication** — send an API key as `X-API-Key` or `Authorization: Bearer <key>`.
Scopes: `read` (query), `write` (submit jobs), `admin` (configuration and keys).

**Search** — `/logs/search` accepts an expression language:
`service=payment AND level=ERROR`, `status_code>=500`, `endpoint~/api/*`,
`level=ERROR,CRITICAL`, or bare text for a full-text match.

**Time windows** — every analytics endpoint takes `start`/`end` (ISO-8601 UTC)
or `hours` for a rolling window ending now.
"""


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request id, times the request and logs its outcome."""

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: DispatchNext) -> Response:
        # Honour an inbound correlation id so a trace spans services, but bound
        # its length — it is echoed into every log line.
        incoming = request.headers.get("x-request-id", "")[:64]
        request_id = set_request_id(incoming or None)
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration = time.perf_counter() - started
            log.exception(
                "request failed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "duration": round(duration, 6),
                    "status": 500,
                },
            )
            global_metrics.increment("http_requests_failed")
            raise

        duration = time.perf_counter() - started
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-ms"] = f"{duration * 1000:.2f}"
        global_metrics.increment("http_requests")
        global_metrics.observe("http_request", duration)
        if response.status_code >= 500:
            global_metrics.increment("http_requests_failed")
        log.info(
            "request completed",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration": round(duration, 6),
            },
        )
        return response


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start-up and shutdown."""
    settings: Settings = app.state.settings
    log.info(
        "api starting",
        extra={
            "version": __version__,
            "environment": settings.environment,
            "auth_required": settings.api.auth_required,
        },
    )
    if not settings.api.auth_required:
        log.warning("authentication is DISABLED; never do this outside development")
    try:
        from app.storage import MetadataStore

        store = MetadataStore.from_settings(settings)
        store.create_schema()
        store.close()
    except Exception:  # noqa: BLE001 - metadata is not required to serve reads
        log.warning("could not initialise the metadata store; continuing read-only")

    yield

    from app.api.deps import reset_dependencies
    from app.workers.queue import shutdown_queue

    shutdown_queue()
    reset_dependencies()
    log.info("api stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application."""
    config = settings or get_settings()
    configure_from_settings(config)

    app = FastAPI(
        title=config.api.title,
        description=DESCRIPTION,
        version=__version__,
        lifespan=lifespan,
        root_path=config.api.root_path,
        # Docs are disabled in production by configuration validation: an
        # interactive schema browser is a map of the attack surface.
        docs_url="/docs" if config.api.docs_enabled else None,
        redoc_url="/redoc" if config.api.docs_enabled else None,
        openapi_url="/openapi.json" if config.api.docs_enabled else None,
    )
    app.state.settings = config
    # Every dependency resolves settings through ``get_settings``; overriding it
    # here is what makes an explicitly-passed Settings object authoritative for
    # this app instance (tests, multi-tenant hosting) instead of the process
    # cache silently winning.
    app.dependency_overrides[get_settings] = lambda: config

    # Added last == outermost, so this list reads inner → outer.
    if config.api.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(config.api.cors_origins),
            allow_credentials=False,  # bearer tokens, not cookies
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["Authorization", "X-API-Key", "Content-Type", "X-Request-ID"],
            max_age=600,
        )
    app.add_middleware(RateLimitMiddleware, settings=config)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware, max_bytes=config.api.max_request_bytes)
    app.add_middleware(SecurityHeadersMiddleware, hsts=config.api.hsts_enabled)

    install_error_handlers(app)

    app.include_router(health.router)
    app.include_router(logs.router)
    app.include_router(analytics.router)
    app.include_router(reports.router)
    app.include_router(jobs.router)
    app.include_router(admin.router)

    if config.api.enable_dashboard:
        from app.dashboard import mount_dashboard

        mount_dashboard(app)

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, Any]:
        return {
            "name": config.api.title,
            "version": __version__,
            "docs": "/docs" if config.api.docs_enabled else None,
            "dashboard": "/dashboard" if config.api.enable_dashboard else None,
            "health": "/health",
        }

    return app


def run() -> None:  # pragma: no cover - process entry point
    """``python -m app.api.main`` / container entry point."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "app.api.main:create_app",
        factory=True,
        host=settings.api.host,
        port=settings.api.port,
        log_config=None,  # the platform owns logging
        access_log=False,  # RequestContextMiddleware already logs, with masking
    )


if __name__ == "__main__":  # pragma: no cover
    run()
