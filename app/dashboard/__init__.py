"""Analytics dashboard.

A small set of static files served from the API's own origin.

Why no framework and no CDN
---------------------------
The API sets a strict Content-Security-Policy (``default-src 'self'`` with no
``'unsafe-inline'``).  A dashboard that pulled React or Chart.js from a CDN
would either fail to load or force that policy open — and a relaxed CSP on the
page that renders log data is exactly where a stored-XSS payload in a log
message becomes an account takeover.  The charts are therefore hand-drawn SVG
in vanilla JavaScript: no supply chain, no build step, and the CSP stays tight.

Why the stylesheet and the script are separate files
----------------------------------------------------
``script-src 'unsafe-inline'`` is precisely the directive that gives XSS its
value back, so an inline ``<script>`` block would have cost the page the
protection this design exists to keep.  Both assets are served from this
origin instead, which lets the policy name ``'self'`` and nothing else.

All rendering uses ``textContent``, never ``innerHTML``, for any value that
came from log data.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, Response

from app.core.logging import get_logger

log = get_logger(__name__)

STATIC_DIR = Path(__file__).parent / "static"
INDEX_FILE = STATIC_DIR / "index.html"

#: Asset name -> (file, media type).  A fixed table, not a directory listing:
#: a name that is not a key here is simply not a route.
ASSETS: Final[dict[str, tuple[Path, str]]] = {
    "dashboard.css": (STATIC_DIR / "dashboard.css", "text/css; charset=utf-8"),
    "dashboard.js": (STATIC_DIR / "dashboard.js", "text/javascript; charset=utf-8"),
}

_MISSING_PAGE: Final[str] = (
    "<!doctype html><html><body><p>Dashboard assets are missing.</p></body></html>"
)


def dashboard_html(base_path: str = "/dashboard") -> str:
    """Read the dashboard page, pointing it at the assets under ``base_path``."""
    if not INDEX_FILE.is_file():  # pragma: no cover - packaging error
        return _MISSING_PAGE
    page = INDEX_FILE.read_text(encoding="utf-8")
    return page.replace("{{base}}", base_path.rstrip("/"))


def dashboard_asset(name: str) -> str:
    """Read one of the dashboard's static assets."""
    path, _ = ASSETS[name]
    if not path.is_file():  # pragma: no cover - packaging error
        return ""
    return path.read_text(encoding="utf-8")


def mount_dashboard(app: FastAPI, path: str = "/dashboard") -> None:
    """Serve the dashboard and its two assets under ``path``.

    Deliberately *not* a ``StaticFiles`` mount: each route serves one known
    file, so there is no name to traverse and no directory to enumerate.
    """
    base = path.rstrip("/") or "/dashboard"

    @app.get(base, include_in_schema=False, response_class=HTMLResponse)
    async def dashboard() -> HTMLResponse:
        return HTMLResponse(content=dashboard_html(base))

    @app.get(f"{base}/dashboard.css", include_in_schema=False)
    async def dashboard_css() -> Response:
        return Response(
            content=dashboard_asset("dashboard.css"), media_type=ASSETS["dashboard.css"][1]
        )

    @app.get(f"{base}/dashboard.js", include_in_schema=False)
    async def dashboard_js() -> Response:
        return Response(
            content=dashboard_asset("dashboard.js"), media_type=ASSETS["dashboard.js"][1]
        )

    log.debug("dashboard mounted", extra={"path": base})


__all__ = [
    "ASSETS",
    "INDEX_FILE",
    "STATIC_DIR",
    "dashboard_asset",
    "dashboard_html",
    "mount_dashboard",
]
