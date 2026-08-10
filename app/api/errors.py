"""API error handling.

One envelope for every failure::

    {"error": {"code": "...", "message": "...", "request_id": "..."}}

Security
--------
The boundary between *internal* and *public* error text is enforced here and
nowhere else:

* Platform exceptions expose ``public_message`` only.  Their ``context`` —
  which may contain file paths, SQL fragments or hostnames — is logged, never
  returned.
* Unexpected exceptions become a generic 500.  A stack trace in an HTTP
  response is reconnaissance: it reveals the framework, the file layout and
  often the query that failed.
* Every response carries the ``request_id``, so a user can quote it and an
  operator can find the full detail in the logs.  That is how you stay
  debuggable without leaking.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    LogAnalyticsError,
    PathTraversalError,
    QueryError,
    RateLimitExceededError,
    SearchSyntaxError,
    StorageError,
)
from app.core.logging import get_logger, request_id_var
from app.core.masking import default_masker

log = get_logger(__name__)

#: Platform exception → HTTP status.  Anything unmapped becomes a 500.
_STATUS_MAP: dict[type[Exception], int] = {
    AuthenticationError: status.HTTP_401_UNAUTHORIZED,
    AuthorizationError: status.HTTP_403_FORBIDDEN,
    RateLimitExceededError: status.HTTP_429_TOO_MANY_REQUESTS,
    SearchSyntaxError: status.HTTP_400_BAD_REQUEST,
    QueryError: status.HTTP_400_BAD_REQUEST,
    PathTraversalError: status.HTTP_400_BAD_REQUEST,
    ConfigurationError: status.HTTP_500_INTERNAL_SERVER_ERROR,
    StorageError: status.HTTP_503_SERVICE_UNAVAILABLE,
}


def error_response(code: str, message: str, status_code: int, **extra: Any) -> JSONResponse:
    payload: dict[str, Any] = {"code": code, "message": message}
    request_id = request_id_var.get()
    if request_id:
        payload["request_id"] = request_id
    payload.update(extra)
    return JSONResponse(status_code=status_code, content={"error": payload})


def install_error_handlers(app: FastAPI) -> None:
    """Register every exception handler on the application."""

    @app.exception_handler(LogAnalyticsError)
    async def _platform_error(_: Request, exc: LogAnalyticsError) -> JSONResponse:
        status_code = next(
            (code for kind, code in _STATUS_MAP.items() if isinstance(exc, kind)),
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )
        # Full detail (including context) goes to the log, masked.
        log.warning(
            "request failed",
            extra={
                "error_code": exc.code,
                "error_type": type(exc).__name__,
                "detail": default_masker.mask_text(str(exc))[:500],
                "context": default_masker.mask_mapping(exc.context),
            },
        )
        return error_response(exc.code, exc.public_message, status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Field-level detail is safe and genuinely useful: it describes the
        # caller's own request, not the server.
        details = [
            {
                "field": ".".join(str(part) for part in error.get("loc", ())[1:]),
                "message": str(error.get("msg", ""))[:200],
            }
            for error in exc.errors()[:20]
        ]
        return error_response(
            "validation_error",
            "The request parameters are invalid.",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details,
        )

    # Registered against Starlette's class, not FastAPI's subclass: the router
    # raises the base class for an unmatched route, and a handler bound to the
    # subclass would silently miss every 404.
    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        response = error_response(
            _CODE_BY_STATUS.get(exc.status_code, "http_error"),
            str(exc.detail),
            exc.status_code,
        )
        for header, value in (exc.headers or {}).items():
            response.headers[header] = value
        return response

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, _exc: Exception) -> JSONResponse:
        log.exception(
            "unhandled exception",
            extra={"path": request.url.path, "method": request.method},
        )
        return error_response(
            "internal_error",
            "An internal error occurred. Quote the request id when reporting it.",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


_CODE_BY_STATUS: dict[int, str] = {
    400: "bad_request",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    413: "payload_too_large",
    422: "validation_error",
    429: "rate_limited",
    500: "internal_error",
    503: "service_unavailable",
}


__all__ = ["error_response", "install_error_handlers"]
