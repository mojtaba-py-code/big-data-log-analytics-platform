"""Big Data Log Analytics Platform.

A modular, production-grade pipeline for ingesting, parsing, validating,
normalizing, de-duplicating, analyzing and serving very large log datasets.

The public surface intentionally stays small: consumers should depend on the
sub-package interfaces (``app.ingestion``, ``app.parsers``, ``app.storage`` …)
rather than on concrete implementations.
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = ["__version__"]
