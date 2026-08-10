"""Analytics dashboard.

A single self-contained HTML page served from the API's own origin.

Why no framework and no CDN
---------------------------
The API sets a strict Content-Security-Policy (``default-src 'self'``).  A
dashboard that pulled React or Chart.js from a CDN would either fail to load or
force that policy open — and a relaxed CSP on the page that renders log data is
exactly where a stored-XSS payload in a log message becomes an account
takeover.  The charts are therefore hand-drawn SVG in vanilla JavaScript:
no supply chain, no build step, and the CSP stays tight.

All rendering uses ``textContent``, never ``innerHTML``, for any value that
came from log data.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app.core.logging import get_logger

log = get_logger(__name__)

STATIC_DIR = Path(__file__).parent / "static"
INDEX_FILE = STATIC_DIR / "index.html"


def dashboard_html() -> str:
    """Read the dashboard page from disk."""
    if not INDEX_FILE.is_file():  # pragma: no cover - packaging error
        return "<!doctype html><html><body><p>Dashboard assets are missing.</p></body></html>"
    return INDEX_FILE.read_text(encoding="utf-8")


def mount_dashboard(app: FastAPI, path: str = "/dashboard") -> None:
    """Serve the dashboard at ``path``.

    Deliberately *not* a ``StaticFiles`` mount: one route serving one known
    file cannot be tricked into serving something else, and there is no
    directory to traverse.
    """

    @app.get(path, include_in_schema=False, response_class=HTMLResponse)
    async def dashboard() -> HTMLResponse:
        return HTMLResponse(content=dashboard_html())

    log.debug("dashboard mounted", extra={"path": path})


__all__ = ["INDEX_FILE", "STATIC_DIR", "dashboard_html", "mount_dashboard"]
