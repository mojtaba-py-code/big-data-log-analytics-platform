"""Ingestion from external REST APIs.

Responsibility
--------------
Pull log records from an HTTP endpoint, following cursor/page pagination, and
yield them as raw records.

Security: SSRF is the dominant risk
-----------------------------------
The URL is operator-supplied and the process usually sits inside a private
network next to a cloud metadata service.  Controls applied here:

1. **Scheme allow-list** — only ``http`` and ``https``.  No ``file://``,
   ``gopher://`` or ``ftp://``.
2. **DNS resolution before connecting** — every resolved address is checked
   against private, loopback, link-local, reserved and multicast ranges.  This
   blocks ``http://169.254.169.254/`` (cloud credentials) and
   ``http://localhost:6379`` (Redis), including via a hostname that resolves
   to them.
3. **Redirects are not followed automatically** — each hop is re-validated,
   which closes the "public URL redirects to 169.254.169.254" bypass.
4. **Response size and time caps** — a hostile endpoint cannot stream forever.
5. **Credentials from configuration, never from the URL**, and the URL is
   logged without its query string (tokens live there).

``allow_private_network_sources`` exists because pulling from an internal log
API is a legitimate deployment; it must be enabled deliberately, and the
platform logs loudly when it is.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator, Mapping
from functools import partial
from typing import Any, Final
from urllib.parse import urlparse, urlsplit, urlunsplit

from app.core.exceptions import IngestionError, SecurityError
from app.core.logging import get_logger
from app.core.retry import RetryPolicy, call_with_retry
from app.ingestion.base import LogSource, RawRecord, source_registry
from app.models.enums import SourceType

log = get_logger(__name__)

ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})
MAX_REDIRECTS: Final[int] = 3
MAX_PAGES: Final[int] = 10_000


def _is_public_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def redact_url(url: str) -> str:
    """URL without query string or credentials — safe for logs."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, "", ""))


def assert_url_allowed(url: str, *, allow_private: bool = False) -> None:
    """Validate scheme and destination address before any connection."""
    parts = urlparse(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise SecurityError("only http and https URLs may be ingested", scheme=parts.scheme)
    host = parts.hostname
    if not host:
        raise SecurityError("the source URL has no host")
    if allow_private:
        return
    try:
        infos = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise IngestionError("could not resolve the source host", host=host) from exc
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise IngestionError("the source host resolved to no addresses", host=host)
    blocked = [addr for addr in addresses if not _is_public_address(str(addr))]
    if blocked:
        raise SecurityError(
            "the source host resolves to a private or reserved address; "
            "set ingestion.allow_private_network_sources to permit this",
            host=host,
        )


@source_registry.register("api", "http", "rest")
class ApiSource(LogSource):
    """Streams records from a paginated JSON REST endpoint."""

    name = "api"
    source_type = SourceType.API

    def __init__(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        records_path: str = "",
        next_cursor_path: str = "",
        cursor_param: str = "cursor",
        page_param: str | None = None,
        max_pages: int = 100,
        timeout_seconds: float = 30.0,
        max_bytes: int = 256 * 1024 * 1024,
        allow_private: bool = False,
        verify_tls: bool = True,
    ) -> None:
        super().__init__()
        assert_url_allowed(url, allow_private=allow_private)
        self.url = url
        self.method = method.upper()
        self.headers = dict(headers or {})
        self.params = dict(params or {})
        self.records_path = records_path
        self.next_cursor_path = next_cursor_path
        self.cursor_param = cursor_param
        self.page_param = page_param
        self.max_pages = min(max_pages, MAX_PAGES)
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self.allow_private = allow_private
        #: Disabling verification is occasionally required for an internal CA;
        #: it is never the default and is logged when used.
        self.verify_tls = verify_tls
        if not verify_tls:
            log.warning(
                "TLS verification is disabled for an API source", extra={"url": redact_url(url)}
            )

    def describe(self) -> str:
        return redact_url(self.url)

    def read(self) -> Iterator[RawRecord]:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - optional extra
            raise IngestionError(
                "httpx is required for API ingestion (pip install 'big-data-log-analytics[api]')"
            ) from exc

        policy = RetryPolicy(
            attempts=3,
            base_delay=1.0,
            retry_on=(httpx.TransportError, httpx.HTTPStatusError, TimeoutError),
        )
        source = self.describe()
        cursor: str | None = None
        page = 0
        total_bytes = 0

        with httpx.Client(
            timeout=self.timeout_seconds,
            follow_redirects=False,  # each hop is re-validated below
            verify=self.verify_tls,
            headers={"Accept": "application/json", **self.headers},
        ) as client:
            while page < self.max_pages:
                params = dict(self.params)
                if cursor is not None:
                    params[self.cursor_param] = cursor
                elif self.page_param:
                    params[self.page_param] = page + 1

                payload = call_with_retry(
                    partial(self._fetch, client, self.url, params),
                    policy,
                    description=f"GET {source}",
                )
                body, size = payload
                total_bytes += size
                self.stats.bytes_read = total_bytes
                if total_bytes > self.max_bytes:
                    raise IngestionError(
                        "API response exceeded the configured byte limit",
                        limit=self.max_bytes,
                    )

                records = _extract(body, self.records_path)
                if isinstance(records, Mapping):
                    records = [records]
                if not isinstance(records, list) or not records:
                    return
                for item in records:
                    if not isinstance(item, dict):
                        self.stats.errors += 1
                        continue
                    self.stats.records_read += 1
                    yield RawRecord(
                        payload=item, source=source, line_number=self.stats.records_read
                    )

                page += 1
                cursor = (
                    str(_extract(body, self.next_cursor_path))
                    if self.next_cursor_path and _extract(body, self.next_cursor_path)
                    else None
                )
                if not cursor and not self.page_param:
                    return

    def _fetch(self, client: Any, url: str, params: Mapping[str, Any]) -> tuple[Any, int]:
        """One request, following redirects manually with re-validation."""
        import httpx

        current = url
        for _ in range(MAX_REDIRECTS + 1):
            response = client.request(self.method, current, params=params)
            if response.is_redirect:
                location = response.headers.get("location", "")
                if not location:
                    break
                current = str(httpx.URL(current).join(location))
                # The whole point: a redirect target is a *new* destination and
                # gets the same SSRF checks as the original URL.
                assert_url_allowed(current, allow_private=self.allow_private)
                params = {}
                continue
            response.raise_for_status()
            content = response.content
            if len(content) > self.max_bytes:
                raise IngestionError("API response body exceeds the byte limit")
            try:
                return response.json(), len(content)
            except ValueError as exc:
                raise IngestionError("API response is not valid JSON") from exc
        raise IngestionError("too many redirects", limit=MAX_REDIRECTS)


def _extract(payload: Any, path: str) -> Any:
    """Follow a dotted path into a decoded JSON body (``data.items``)."""
    if not path:
        return payload
    current = payload
    for part in path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return None
    return current


__all__ = ["ALLOWED_SCHEMES", "ApiSource", "assert_url_allowed", "redact_url"]
