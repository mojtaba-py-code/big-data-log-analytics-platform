"""Report generation.

A report is the union of every analytics view over one window, plus anomalies
and security findings, rendered as JSON, Markdown or HTML.

Reports are *snapshots*: they are computed once and stored, so an incident
review months later sees exactly what the on-call engineer saw, not what a
re-query of (possibly expired) data would return today.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.analytics.engine import AnalyticsEngine
from app.analytics.security import SecurityAnalyzer
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.paths import ensure_directory, safe_filename
from app.core.timeutil import parse_range, to_iso, utcnow
from app.models.analytics import Report, TimeRange

if TYPE_CHECKING:
    from app.anomaly_detection.service import AnomalyService

log = get_logger(__name__)


class ReportBuilder:
    """Assembles a :class:`Report` from the analytics services."""

    def __init__(
        self,
        settings: Settings | None = None,
        analytics: AnalyticsEngine | None = None,
        anomalies: AnomalyService | None = None,
        security: SecurityAnalyzer | None = None,
    ) -> None:
        # Imported here, not at module scope: app.anomaly_detection.detectors
        # pulls in app.analytics.statistics, which runs this package's __init__,
        # which imports this module.  Whichever of the two packages is imported
        # first wins, so a module-level import made `import app.anomaly_detection`
        # fail with a partially-initialised `detectors` — as it did inside the
        # container image, where the CLI entrypoint reaches it first.
        from app.anomaly_detection.service import AnomalyService

        self.settings = settings or get_settings()
        self.analytics = analytics or AnalyticsEngine(settings=self.settings)
        self.anomalies = anomalies or AnomalyService(self.analytics, self.settings)
        self.security = security or SecurityAnalyzer(self.analytics.engine, self.settings)

    def build(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        *,
        name: str = "Log Analytics Report",
        filters: Mapping[str, Any] | None = None,
        window: str | None = None,
        include_anomalies: bool = True,
        include_security: bool = True,
    ) -> Report:
        start_dt, end_dt = parse_range(start, end)
        bucket = window or self.settings.analytics.default_window
        log.info(
            "building report",
            extra={"start": to_iso(start_dt), "end": to_iso(end_dt), "window": bucket},
        )

        overview = self.analytics.overview(start_dt, end_dt, filters)
        sections: dict[str, Any] = {
            "errors": self.analytics.errors(start_dt, end_dt, filters, window=bucket),
            "status_codes": self.analytics.status_codes(start_dt, end_dt, filters),
            "latency": self.analytics.latency(start_dt, end_dt, filters, window=bucket),
            "traffic": self.analytics.traffic(start_dt, end_dt, filters, window=bucket),
            "services": self.analytics.services(start_dt, end_dt, filters),
        }

        found_anomalies = (
            self.anomalies.scan(start_dt, end_dt, window=bucket, filters=filters)
            if include_anomalies and self.settings.analytics.enable_anomaly_detection
            else []
        )
        findings = (
            self.security.analyze(start_dt, end_dt)
            if include_security and self.settings.security_analytics.enabled
            else []
        )
        overview = overview.model_copy(
            update={
                "anomalies": len(found_anomalies),
                "suspicious_events": sum(f.event_count for f in findings),
            }
        )

        return Report(
            name=name,
            time_range=TimeRange(start=start_dt, end=end_dt),
            overview=overview,
            sections=sections,
            anomalies=found_anomalies,
            security_findings=findings,
        )

    def daily(self, day: datetime | None = None, **kwargs: Any) -> Report:
        """Report covering one calendar day (UTC)."""
        anchor = day or (utcnow() - timedelta(days=1))
        start = anchor.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1) - timedelta(microseconds=1)
        return self.build(start, end, name=f"Daily Report {start.date().isoformat()}", **kwargs)

    def summary(self, hours: float = 24.0, **kwargs: Any) -> Report:
        """Rolling window ending now."""
        end = utcnow()
        return self.build(
            end - timedelta(hours=hours), end, name=f"Last {hours:g}h Summary", **kwargs
        )


def render_json(report: Report, *, indent: int = 2) -> str:
    return report.model_dump_json(indent=indent)


def render_markdown(report: Report) -> str:
    """Markdown with the analytics sections appended to the base rendering."""
    lines = [report.to_markdown()]
    traffic = report.sections.get("traffic")
    if traffic is not None and traffic.top_endpoints:
        lines += [
            "## Top endpoints",
            "",
            "| Endpoint | Requests | Share |",
            "| --- | ---: | ---: |",
        ]
        lines += [
            f"| `{item.key}` | {item.count:,} | {item.percentage:.1f}% |"
            for item in traffic.top_endpoints
        ]
        lines.append("")
    services = report.sections.get("services")
    if services is not None and services.services:
        lines += [
            "## Service health",
            "",
            "| Service | Requests | Errors | Failure rate | P95 (ms) | Status |",
            "| --- | ---: | ---: | ---: | ---: | --- |",
        ]
        lines += [
            f"| {s.service} | {s.requests:,} | {s.errors:,} | {s.failure_rate:.2%} "
            f"| {s.latency.p95:.1f} | {s.status} |"
            for s in services.services
        ]
        lines.append("")
    status = report.sections.get("status_codes")
    if status is not None and status.by_class:
        lines += ["## Status codes", "", "| Class | Count |", "| --- | ---: |"]
        lines += [f"| {name} | {count:,} |" for name, count in sorted(status.by_class.items())]
        lines.append("")
    return "\n".join(lines)


def render_html(report: Report) -> str:
    """Minimal self-contained HTML — no external assets, safe to email."""
    import html

    body = html.escape(render_markdown(report))
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{html.escape(report.name)}</title>"
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;max-width:60rem}"
        "pre{white-space:pre-wrap;line-height:1.5}</style></head>"
        f"<body><pre>{body}</pre></body></html>"
    )


def save_report(
    report: Report, directory: Path, *, fmt: str = "json", filename: str | None = None
) -> Path:
    """Write a report to disk with a safe, deterministic name."""
    ensure_directory(directory)
    renderers = {
        "json": render_json,
        "markdown": render_markdown,
        "md": render_markdown,
        "html": render_html,
    }
    render = renderers.get(fmt)
    if render is None:
        raise ValueError(f"unsupported report format {fmt!r}; choose from {sorted(renderers)}")
    extension = {"markdown": "md", "md": "md", "json": "json", "html": "html"}[fmt]
    stamp = report.time_range.start.strftime("%Y%m%d")
    name = safe_filename(filename or f"{report.name.lower().replace(' ', '-')}-{stamp}.{extension}")
    path = directory / name
    path.write_text(render(report), encoding="utf-8")
    log.info("report written", extra={"path": str(path), "format": fmt})
    return path


def load_report(path: Path) -> Report:
    """Read a JSON report back (for diffing or re-rendering)."""
    return Report.model_validate(json.loads(path.read_text(encoding="utf-8")))


__all__ = [
    "ReportBuilder",
    "load_report",
    "render_html",
    "render_json",
    "render_markdown",
    "save_report",
]
