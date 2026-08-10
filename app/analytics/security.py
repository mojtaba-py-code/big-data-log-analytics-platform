"""Security analytics.

Responsibility
--------------
Surface *suspicious* behaviour in the logs and score it, so an operator can
triage.  Strictly detection and reporting: nothing here blocks, bans, probes or
retaliates.  The platform reads logs; it has no business acting on the network.

Detections
----------
=============================  ===========================================
Finding                        Signal
=============================  ===========================================
``brute_force``                Many 401/403 from one IP inside a window.
``credential_stuffing``        Failed auth from one IP across many users.
``endpoint_scanning``          Many distinct 404 paths from one IP.
``sensitive_endpoint_access``  Requests to ``/.env``, ``/admin`` and friends.
``suspicious_user_agent``      Known scanner/tool signatures.
``request_flood``              Request rate far above the population norm.
``secret_in_log``              The masking layer redacted a credential —
                               an application is logging secrets.
=============================  ===========================================

Risk scoring
------------
Each finding starts from a base score for its class and is adjusted by volume
(logarithmic — 10 000 attempts is worse than 100, but not 100x worse), by how
many *distinct* signals the same subject triggers, and by whether the source is
a public address.  Scores are 0-100 and map onto
:meth:`app.models.enums.Severity.from_score`.

False positives are expected and acknowledged: a load balancer health check, a
CI runner or a corporate NAT can all look like a flood.  That is why findings
carry their evidence — a score without evidence cannot be triaged.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Final

from app.core.config import SecurityAnalyticsSettings, Settings, get_settings
from app.core.logging import get_logger
from app.core.timeutil import ensure_utc, parse_range, utcnow
from app.models.analytics import SecurityFinding
from app.models.enums import SecurityFindingType, Severity
from app.storage.duckdb_engine import DuckDBEngine

log = get_logger(__name__)

#: Base risk score per finding class, before volume and correlation adjustment.
BASE_SCORES: Final[dict[SecurityFindingType, float]] = {
    SecurityFindingType.BRUTE_FORCE: 55.0,
    SecurityFindingType.CREDENTIAL_STUFFING: 70.0,
    SecurityFindingType.ENDPOINT_SCANNING: 45.0,
    SecurityFindingType.SENSITIVE_ENDPOINT_ACCESS: 60.0,
    SecurityFindingType.SUSPICIOUS_USER_AGENT: 35.0,
    SecurityFindingType.REQUEST_FLOOD: 40.0,
    SecurityFindingType.SECRET_IN_LOG: 65.0,
    SecurityFindingType.ANOMALOUS_ERROR_RATE: 30.0,
}

#: Failed-authentication status codes.
_AUTH_FAILURE_STATUSES: Final[tuple[int, ...]] = (401, 403)

MAX_FINDINGS_PER_TYPE: Final[int] = 50


def score_finding(
    finding_type: SecurityFindingType,
    *,
    volume: int,
    distinct: int = 1,
    public_source: bool = True,
    correlated_signals: int = 1,
) -> float:
    """Combine base risk, volume, breadth and correlation into 0-100."""
    base = BASE_SCORES.get(finding_type, 30.0)
    # log10 keeps the scale sane: 10 → +8, 100 → +16, 10 000 → +32.
    volume_bonus = min(32.0, 8.0 * math.log10(max(volume, 1)))
    breadth_bonus = min(10.0, 2.5 * math.log10(max(distinct, 1)) * 2)
    correlation_bonus = min(15.0, (correlated_signals - 1) * 7.5)
    penalty = 0.0 if public_source else 12.0  # internal sources are lower risk
    return round(
        max(0.0, min(100.0, base + volume_bonus + breadth_bonus + correlation_bonus - penalty)), 2
    )


class SecurityAnalyzer:
    """Runs the security detections over the processed dataset."""

    def __init__(
        self,
        engine: DuckDBEngine | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.config: SecurityAnalyticsSettings = self.settings.security_analytics
        if engine is None:
            from app.storage import build_engine

            engine = build_engine(self.settings)
        self.engine = engine

    # -- entry point ---------------------------------------------------------- #
    def analyze(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        *,
        limit: int = 100,
    ) -> list[SecurityFinding]:
        """Run every detection and return correlated, ranked findings."""
        if not self.config.enabled:
            return []
        start_dt, end_dt = parse_range(start, end)
        scan = self.engine.scan(start_dt, end_dt)
        if scan is None:
            return []
        source, scan_params = scan
        window = (
            source,
            "timestamp >= ? AND timestamp <= ?",
            [*scan_params, start_dt, end_dt],
        )

        findings: list[SecurityFinding] = []
        for detection in (
            self._failed_authentication,
            self._credential_stuffing,
            self._endpoint_scanning,
            self._sensitive_endpoints,
            self._suspicious_user_agents,
            self._request_floods,
            self._secrets_in_logs,
        ):
            try:
                findings.extend(detection(*window))
            except Exception:  # noqa: BLE001 - one detection must not stop the rest
                log.exception("security detection failed", extra={"detection": detection.__name__})

        correlated = self._correlate(findings)
        correlated.sort(key=lambda f: (-f.risk_score, f.subject))
        log.info("security analysis complete", extra={"findings": len(correlated)})
        return correlated[:limit]

    # -- detections ------------------------------------------------------------ #
    def _failed_authentication(
        self, source: str, where: str, params: Sequence[Any]
    ) -> list[SecurityFinding]:
        """Repeated authentication failures from a single address."""
        statuses = ", ".join("?" for _ in _AUTH_FAILURE_STATUSES)
        sql = f"""
            SELECT ip_address                     AS subject,
                   COUNT(*)                       AS attempts,
                   COUNT(DISTINCT user_id)        AS users,
                   COUNT(DISTINCT endpoint)       AS endpoints,
                   MIN(timestamp)                 AS first_seen,
                   MAX(timestamp)                 AS last_seen,
                   any_value(user_agent)          AS user_agent
            FROM {source}
            WHERE {where} AND ip_address IS NOT NULL AND status_code IN ({statuses})
            GROUP BY 1 HAVING COUNT(*) >= ?
            ORDER BY 2 DESC LIMIT ?
        """  # noqa: S608 - source/predicate are platform-built, values are bound
        rows = self.engine.execute(
            sql,
            [
                *params,
                *_AUTH_FAILURE_STATUSES,
                self.config.failed_auth_threshold,
                MAX_FINDINGS_PER_TYPE,
            ],
        )
        findings: list[SecurityFinding] = []
        for row in rows:
            attempts = int(row["attempts"])
            duration = _duration_seconds(row)
            # A burst inside the configured window is the brute-force shape;
            # the same count spread over a day is much weaker evidence.
            concentrated = duration <= self.config.failed_auth_window_seconds or duration == 0
            findings.append(
                self._finding(
                    SecurityFindingType.BRUTE_FORCE,
                    row,
                    volume=attempts,
                    distinct=int(row["endpoints"] or 1),
                    description=(
                        f"{attempts} failed authentications from {row['subject']} "
                        f"over {duration:.0f}s"
                        + ("" if concentrated else " (spread out; lower confidence)")
                    ),
                    evidence={
                        "attempts": attempts,
                        "distinct_users": int(row["users"] or 0),
                        "distinct_endpoints": int(row["endpoints"] or 0),
                        "duration_seconds": round(duration, 1),
                        "user_agent": row.get("user_agent"),
                        "concentrated": concentrated,
                    },
                )
            )
        return findings

    def _credential_stuffing(
        self, source: str, where: str, params: Sequence[Any]
    ) -> list[SecurityFinding]:
        """One address failing auth against many *different* accounts."""
        statuses = ", ".join("?" for _ in _AUTH_FAILURE_STATUSES)
        sql = f"""
            SELECT ip_address              AS subject,
                   COUNT(*)                AS attempts,
                   COUNT(DISTINCT user_id) AS users,
                   MIN(timestamp)          AS first_seen,
                   MAX(timestamp)          AS last_seen
            FROM {source}
            WHERE {where} AND ip_address IS NOT NULL AND user_id IS NOT NULL
              AND status_code IN ({statuses})
            GROUP BY 1 HAVING COUNT(DISTINCT user_id) >= ?
            ORDER BY 3 DESC LIMIT ?
        """  # noqa: S608 - see above
        rows = self.engine.execute(
            sql,
            [
                *params,
                *_AUTH_FAILURE_STATUSES,
                max(5, self.config.failed_auth_threshold),
                MAX_FINDINGS_PER_TYPE,
            ],
        )
        return [
            self._finding(
                SecurityFindingType.CREDENTIAL_STUFFING,
                row,
                volume=int(row["attempts"]),
                distinct=int(row["users"]),
                description=(
                    f"{row['subject']} failed authentication against "
                    f"{int(row['users'])} distinct accounts"
                ),
                evidence={"attempts": int(row["attempts"]), "distinct_users": int(row["users"])},
            )
            for row in rows
        ]

    def _endpoint_scanning(
        self, source: str, where: str, params: Sequence[Any]
    ) -> list[SecurityFinding]:
        """Many distinct 404s from one address — directory/vuln scanning."""
        sql = f"""
            SELECT ip_address                AS subject,
                   COUNT(*)                  AS requests,
                   COUNT(DISTINCT endpoint)  AS paths,
                   MIN(timestamp)            AS first_seen,
                   MAX(timestamp)            AS last_seen,
                   any_value(user_agent)     AS user_agent
            FROM {source}
            WHERE {where} AND ip_address IS NOT NULL AND status_code = 404
            GROUP BY 1 HAVING COUNT(*) >= ?
            ORDER BY 3 DESC LIMIT ?
        """  # noqa: S608 - see above
        rows = self.engine.execute(
            sql, [*params, self.config.not_found_threshold, MAX_FINDINGS_PER_TYPE]
        )
        return [
            self._finding(
                SecurityFindingType.ENDPOINT_SCANNING,
                row,
                volume=int(row["requests"]),
                distinct=int(row["paths"]),
                description=(
                    f"{row['subject']} requested {int(row['paths'])} distinct missing "
                    f"paths ({int(row['requests'])} requests)"
                ),
                evidence={
                    "requests": int(row["requests"]),
                    "distinct_paths": int(row["paths"]),
                    "user_agent": row.get("user_agent"),
                },
            )
            for row in rows
        ]

    def _sensitive_endpoints(
        self, source: str, where: str, params: Sequence[Any]
    ) -> list[SecurityFinding]:
        """Access attempts against configured sensitive paths."""
        patterns = self.config.sensitive_endpoints
        if not patterns:
            return []
        conditions = " OR ".join("endpoint ILIKE ?" for _ in patterns)
        sql = f"""
            SELECT ip_address              AS subject,
                   COUNT(*)                AS requests,
                   COUNT(DISTINCT endpoint) AS paths,
                   MIN(timestamp)          AS first_seen,
                   MAX(timestamp)          AS last_seen,
                   list(DISTINCT endpoint)[1:10] AS sample_paths
            FROM {source}
            WHERE {where} AND ip_address IS NOT NULL AND ({conditions})
            GROUP BY 1 ORDER BY 2 DESC LIMIT ?
        """  # noqa: S608 - patterns are bound parameters, not interpolated
        rows = self.engine.execute(
            sql, [*params, *(f"{pattern}%" for pattern in patterns), MAX_FINDINGS_PER_TYPE]
        )
        return [
            self._finding(
                SecurityFindingType.SENSITIVE_ENDPOINT_ACCESS,
                row,
                volume=int(row["requests"]),
                distinct=int(row["paths"]),
                description=(
                    f"{row['subject']} accessed {int(row['paths'])} sensitive endpoint(s)"
                ),
                evidence={
                    "requests": int(row["requests"]),
                    "paths": list(row.get("sample_paths") or []),
                },
            )
            for row in rows
        ]

    def _suspicious_user_agents(
        self, source: str, where: str, params: Sequence[Any]
    ) -> list[SecurityFinding]:
        """Known scanner and automation signatures."""
        agents = self.config.suspicious_user_agents
        if not agents:
            return []
        conditions = " OR ".join("user_agent ILIKE ?" for _ in agents)
        sql = f"""
            SELECT ip_address           AS subject,
                   COUNT(*)             AS requests,
                   any_value(user_agent) AS user_agent,
                   COUNT(DISTINCT endpoint) AS paths,
                   MIN(timestamp)       AS first_seen,
                   MAX(timestamp)       AS last_seen
            FROM {source}
            WHERE {where} AND ip_address IS NOT NULL AND ({conditions})
            GROUP BY 1 ORDER BY 2 DESC LIMIT ?
        """  # noqa: S608 - agents are bound parameters
        rows = self.engine.execute(
            sql, [*params, *(f"%{agent}%" for agent in agents), MAX_FINDINGS_PER_TYPE]
        )
        return [
            self._finding(
                SecurityFindingType.SUSPICIOUS_USER_AGENT,
                row,
                volume=int(row["requests"]),
                distinct=int(row["paths"] or 1),
                description=(
                    f"{row['subject']} used a known scanner user agent "
                    f"({str(row.get('user_agent'))[:60]})"
                ),
                evidence={
                    "requests": int(row["requests"]),
                    "user_agent": row.get("user_agent"),
                },
            )
            for row in rows
        ]

    def _request_floods(
        self, source: str, where: str, params: Sequence[Any]
    ) -> list[SecurityFinding]:
        """Addresses whose request rate dwarfs the configured threshold."""
        sql = f"""
            SELECT ip_address       AS subject,
                   COUNT(*)         AS requests,
                   COUNT(DISTINCT endpoint) AS paths,
                   MIN(timestamp)   AS first_seen,
                   MAX(timestamp)   AS last_seen
            FROM {source}
            WHERE {where} AND ip_address IS NOT NULL
            GROUP BY 1 HAVING COUNT(*) >= ?
            ORDER BY 2 DESC LIMIT ?
        """  # noqa: S608 - see above
        rows = self.engine.execute(
            sql, [*params, self.config.request_rate_threshold, MAX_FINDINGS_PER_TYPE]
        )
        findings: list[SecurityFinding] = []
        for row in rows:
            duration = max(_duration_seconds(row), 1.0)
            rate = int(row["requests"]) / duration
            # Only flag rates that are actually high; a busy client over a long
            # window is normal traffic.
            if rate < 1.0:
                continue
            findings.append(
                self._finding(
                    SecurityFindingType.REQUEST_FLOOD,
                    row,
                    volume=int(row["requests"]),
                    distinct=int(row["paths"] or 1),
                    description=(
                        f"{row['subject']} sent {int(row['requests'])} requests "
                        f"({rate:.1f}/s sustained)"
                    ),
                    evidence={
                        "requests": int(row["requests"]),
                        "requests_per_second": round(rate, 2),
                        "duration_seconds": round(duration, 1),
                    },
                )
            )
        return findings

    def _secrets_in_logs(
        self, source: str, where: str, params: Sequence[Any]
    ) -> list[SecurityFinding]:
        """Records the masking layer had to redact.

        The secret itself is already gone by the time it reaches storage — this
        reports the *application* that logged one, which is the actionable part.
        """
        sql = f"""
            SELECT COALESCE(service, 'unknown') AS subject,
                   COUNT(*)                     AS occurrences,
                   COUNT(DISTINCT logger)       AS loggers,
                   MIN(timestamp)               AS first_seen,
                   MAX(timestamp)               AS last_seen
            FROM {source}
            WHERE {where} AND metadata IS NOT NULL AND metadata LIKE '%"masked": true%'
            GROUP BY 1 ORDER BY 2 DESC LIMIT ?
        """  # noqa: S608 - constant predicate
        rows = self.engine.execute(sql, [*params, MAX_FINDINGS_PER_TYPE])
        return [
            self._finding(
                SecurityFindingType.SECRET_IN_LOG,
                row,
                volume=int(row["occurrences"]),
                distinct=int(row["loggers"] or 1),
                public_source=False,
                description=(
                    f"service '{row['subject']}' emitted {int(row['occurrences'])} log "
                    "records containing credentials (redacted on ingest)"
                ),
                evidence={
                    "occurrences": int(row["occurrences"]),
                    "distinct_loggers": int(row["loggers"] or 0),
                },
            )
            for row in rows
        ]

    # -- shaping --------------------------------------------------------------- #
    def _finding(
        self,
        finding_type: SecurityFindingType,
        row: Mapping[str, Any],
        *,
        volume: int,
        distinct: int = 1,
        description: str = "",
        evidence: Mapping[str, Any] | None = None,
        public_source: bool = True,
    ) -> SecurityFinding:
        subject = str(row.get("subject") or "unknown")
        score = score_finding(
            finding_type,
            volume=volume,
            distinct=distinct,
            public_source=public_source and not _is_private(subject),
        )
        now = utcnow()
        return SecurityFinding(
            type=finding_type,
            severity=Severity.from_score(score),
            risk_score=score,
            subject=subject,
            first_seen=ensure_utc(row.get("first_seen") or now),
            last_seen=ensure_utc(row.get("last_seen") or now),
            event_count=volume,
            evidence=dict(evidence or {}),
            description=description,
        )

    def _correlate(self, findings: Sequence[SecurityFinding]) -> list[SecurityFinding]:
        """Raise the score of subjects that trip several distinct detections."""
        by_subject: dict[str, list[SecurityFinding]] = {}
        for finding in findings:
            by_subject.setdefault(finding.subject, []).append(finding)

        out: list[SecurityFinding] = []
        for subject, group in by_subject.items():
            signals = len({f.type for f in group})
            for finding in group:
                if signals <= 1:
                    out.append(finding)
                    continue
                score = score_finding(
                    finding.type,
                    volume=finding.event_count,
                    distinct=max(1, len(finding.evidence)),
                    public_source=not _is_private(subject),
                    correlated_signals=signals,
                )
                out.append(
                    finding.model_copy(
                        update={
                            "risk_score": score,
                            "severity": Severity.from_score(score),
                            "evidence": {**finding.evidence, "correlated_signals": signals},
                        }
                    )
                )
        return out

    def close(self) -> None:
        self.engine.close()


def _duration_seconds(row: Mapping[str, Any]) -> float:
    first, last = row.get("first_seen"), row.get("last_seen")
    if not isinstance(first, datetime) or not isinstance(last, datetime):
        return 0.0
    return max((ensure_utc(last) - ensure_utc(first)).total_seconds(), 0.0)


def _is_private(subject: str) -> bool:
    import ipaddress

    try:
        address = ipaddress.ip_address(subject)
    except ValueError:
        return False
    return address.is_private or address.is_loopback


__all__ = ["BASE_SCORES", "SecurityAnalyzer", "score_finding"]
