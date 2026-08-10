"""Cross-cutting infrastructure shared by every layer.

Nothing in :mod:`app.core` may import from a higher layer (ingestion, parsers,
analytics, api …).  The dependency arrow points inwards only, which is what
keeps the core independently testable and the layers replaceable.
"""

from __future__ import annotations

from app.core.config import Settings, get_settings, load_settings
from app.core.exceptions import LogAnalyticsError
from app.core.logging import configure_logging, get_logger
from app.core.metrics import MetricsRegistry
from app.core.registry import Registry

__all__ = [
    "LogAnalyticsError",
    "MetricsRegistry",
    "Registry",
    "Settings",
    "configure_logging",
    "get_logger",
    "get_settings",
    "load_settings",
]
