"""Analytics, anomaly and security result models.

These are the contract between the analytics engine and everything that
consumes it (API, dashboard, reports, CLI).  Keeping them as explicit models —
rather than passing bare dicts around — means the API's OpenAPI schema is
generated from the same definitions the engine fills in, so the two cannot
drift apart.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer

from app.core.timeutil import to_iso, utcnow
from app.models.enums import AnomalyType, SecurityFindingType, Severity


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @field_serializer("*", when_used="json")
    def _serialize_datetimes(self, value: Any) -> Any:
        return to_iso(value) if isinstance(value, datetime) else value


class TimeRange(_Model):
    start: datetime
    end: datetime

    @property
    def seconds(self) -> float:
        return max((self.end - self.start).total_seconds(), 0.0)


class Stats(_Model):
    """Descriptive statistics for one numeric series."""

    count: int = 0
    sum: float = 0.0
    average: float = 0.0
    minimum: float = 0.0
    maximum: float = 0.0
    median: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    stddev: float = 0.0


class TimeSeriesPoint(_Model):
    """One aggregation bucket."""

    bucket: datetime
    count: int = 0
    value: float = 0.0
    extra: dict[str, float] = Field(default_factory=dict)


class TimeSeries(_Model):
    metric: str
    window: str
    points: list[TimeSeriesPoint] = Field(default_factory=list)

    @property
    def values(self) -> list[float]:
        return [p.value for p in self.points]

    @property
    def total(self) -> float:
        return sum(self.values)


class CountItem(_Model):
    """A ``(key, count)`` pair with its share of the whole — for top-N lists."""

    key: str
    count: int
    percentage: float = 0.0


class ErrorAnalytics(_Model):
    time_range: TimeRange
    total_records: int = 0
    total_errors: int = 0
    error_rate: float = 0.0
    by_service: list[CountItem] = Field(default_factory=list)
    by_endpoint: list[CountItem] = Field(default_factory=list)
    by_host: list[CountItem] = Field(default_factory=list)
    by_level: list[CountItem] = Field(default_factory=list)
    over_time: TimeSeries | None = None


class StatusCodeAnalytics(_Model):
    time_range: TimeRange
    total_requests: int = 0
    by_class: dict[str, int] = Field(default_factory=dict)
    by_code: list[CountItem] = Field(default_factory=list)
    client_error_rate: float = 0.0
    server_error_rate: float = 0.0
    success_rate: float = 0.0


class LatencyAnalytics(_Model):
    time_range: TimeRange
    overall: Stats = Field(default_factory=Stats)
    by_service: dict[str, Stats] = Field(default_factory=dict)
    by_endpoint: dict[str, Stats] = Field(default_factory=dict)
    over_time: TimeSeries | None = None


class TrafficAnalytics(_Model):
    time_range: TimeRange
    total_requests: int = 0
    requests_per_minute: float = 0.0
    requests_per_hour: float = 0.0
    requests_per_day: float = 0.0
    bytes_sent: int = 0
    top_ips: list[CountItem] = Field(default_factory=list)
    top_endpoints: list[CountItem] = Field(default_factory=list)
    top_user_agents: list[CountItem] = Field(default_factory=list)
    top_methods: list[CountItem] = Field(default_factory=list)
    over_time: TimeSeries | None = None


class ServiceHealth(_Model):
    service: str
    requests: int = 0
    errors: int = 0
    failure_rate: float = 0.0
    availability: float = 100.0
    throughput_per_second: float = 0.0
    latency: Stats = Field(default_factory=Stats)
    status: str = "healthy"


class ServiceAnalytics(_Model):
    time_range: TimeRange
    services: list[ServiceHealth] = Field(default_factory=list)

    @property
    def unhealthy(self) -> list[ServiceHealth]:
        return [s for s in self.services if s.status != "healthy"]


class Anomaly(_Model):
    """A statistically unusual observation."""

    type: AnomalyType
    detector: str
    severity: Severity = Severity.MEDIUM
    bucket: datetime
    metric: str
    observed: float
    expected: float
    deviation: float = 0.0
    score: float = 0.0
    dimension: str | None = None
    description: str = ""

    def as_row(self) -> dict[str, Any]:
        return {
            "type": str(self.type),
            "detector": self.detector,
            "severity": str(self.severity),
            "bucket": self.bucket,
            "metric": self.metric,
            "observed": self.observed,
            "expected": self.expected,
            "deviation": self.deviation,
            "score": self.score,
            "dimension": self.dimension,
            "description": self.description,
        }


class SecurityFinding(_Model):
    """A suspicious pattern with a 0-100 risk score.

    Detection only.  The platform reports and scores; it never blocks, bans or
    attacks back — that is an operator decision made in a system that owns the
    network path.
    """

    type: SecurityFindingType
    severity: Severity = Severity.MEDIUM
    risk_score: float = Field(default=0.0, ge=0, le=100)
    subject: str = Field(description="Entity the finding is about (IP, user, endpoint).")
    first_seen: datetime
    last_seen: datetime
    event_count: int = 0
    evidence: dict[str, Any] = Field(default_factory=dict)
    description: str = ""

    def as_row(self) -> dict[str, Any]:
        return {
            "type": str(self.type),
            "severity": str(self.severity),
            "risk_score": self.risk_score,
            "subject": self.subject,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "evidence": json.dumps(self.evidence, default=str),
            "description": self.description,
        }


class OverviewMetrics(_Model):
    """The dashboard's headline tiles."""

    time_range: TimeRange
    total_records: int = 0
    total_requests: int = 0
    total_errors: int = 0
    error_rate: float = 0.0
    average_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    active_services: int = 0
    suspicious_events: int = 0
    anomalies: int = 0
    generated_at: datetime = Field(default_factory=utcnow)


class Report(_Model):
    """A generated report: headline metrics plus the sections behind them."""

    name: str
    time_range: TimeRange
    generated_at: datetime = Field(default_factory=utcnow)
    overview: OverviewMetrics
    sections: dict[str, Any] = Field(default_factory=dict)
    anomalies: list[Anomaly] = Field(default_factory=list)
    security_findings: list[SecurityFinding] = Field(default_factory=list)

    def to_markdown(self) -> str:
        """Render the report as Markdown for the CLI and for docs/artifacts."""
        lines = [
            f"# {self.name}",
            "",
            f"*Window:* {to_iso(self.time_range.start)} -> {to_iso(self.time_range.end)}  ",
            f"*Generated:* {to_iso(self.generated_at)}",
            "",
            "## Overview",
            "",
            "| Metric | Value |",
            "| --- | ---: |",
            f"| Total records | {self.overview.total_records:,} |",
            f"| Total requests | {self.overview.total_requests:,} |",
            f"| Total errors | {self.overview.total_errors:,} |",
            f"| Error rate | {self.overview.error_rate:.2%} |",
            f"| Avg latency | {self.overview.average_latency_ms:.1f} ms |",
            f"| P95 latency | {self.overview.p95_latency_ms:.1f} ms |",
            f"| P99 latency | {self.overview.p99_latency_ms:.1f} ms |",
            f"| Active services | {self.overview.active_services} |",
            f"| Suspicious events | {self.overview.suspicious_events} |",
            f"| Anomalies | {self.overview.anomalies} |",
            "",
        ]
        if self.anomalies:
            lines += [
                "## Anomalies",
                "",
                "| Time | Type | Metric | Observed | Expected | Severity |",
                "| --- | --- | --- | ---: | ---: | --- |",
            ]
            lines += [
                f"| {to_iso(a.bucket)} | {a.type} | {a.metric} | {a.observed:.2f} "
                f"| {a.expected:.2f} | {a.severity} |"
                for a in self.anomalies[:50]
            ]
            lines.append("")
        if self.security_findings:
            lines += [
                "## Security findings",
                "",
                "| Subject | Type | Events | Risk | Severity |",
                "| --- | --- | ---: | ---: | --- |",
            ]
            lines += [
                f"| {f.subject} | {f.type} | {f.event_count} | {f.risk_score:.0f} | {f.severity} |"
                for f in self.security_findings[:50]
            ]
            lines.append("")
        return "\n".join(lines)


__all__ = [
    "Anomaly",
    "CountItem",
    "ErrorAnalytics",
    "LatencyAnalytics",
    "OverviewMetrics",
    "Report",
    "SecurityFinding",
    "ServiceAnalytics",
    "ServiceHealth",
    "StatusCodeAnalytics",
    "Stats",
    "TimeRange",
    "TimeSeries",
    "TimeSeriesPoint",
    "TrafficAnalytics",
]
