"""Synthetic log generator.

Responsibility
--------------
Produce realistic datasets for benchmarks, demos and tests — at any scale, in
any supported format, deterministically.

Realism that matters for testing analytics
------------------------------------------
Uniform random noise would make every detector look perfect.  The generator
therefore reproduces the structure real log data has:

* **Diurnal traffic** — a sinusoidal request rate, so time-series and anomaly
  code sees a baseline that legitimately varies.
* **Long-tail latency** — log-normal, not uniform: P99 is many times the
  median, which is exactly what makes percentile aggregation non-trivial.
* **Correlated errors** — 5xx responses cluster into incidents rather than
  scattering, so error-spike detection has something real to find.
* **Injected anomalies and attacks** — traffic spikes, latency degradation,
  brute-force bursts, endpoint scanning and scanner user-agents, at known
  timestamps, so detection can be scored against ground truth.
* **Deliberate dirt** — malformed lines, duplicates, bad timestamps and
  invalid IPs at configurable rates, so the DLQ and dedup paths are exercised.

Privacy
-------
Every identifier is generated.  No real person's data, no real IP ranges
beyond the documentation ranges reserved for exactly this purpose
(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
"""

from __future__ import annotations

import gzip
import json
import math
import random
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Final

from app.core.paths import ensure_directory
from app.core.timeutil import to_iso, utcnow

SERVICES: Final[tuple[str, ...]] = (
    "api-gateway",
    "auth",
    "payment",
    "orders",
    "inventory",
    "search",
    "notification",
    "reporting",
    "user-profile",
)

HOSTS: Final[tuple[str, ...]] = tuple(f"host-{i:02d}" for i in range(1, 13))

ENDPOINTS: Final[tuple[tuple[str, str, float], ...]] = (
    ("GET", "/api/v1/products", 0.18),
    ("GET", "/api/v1/products/{id}", 0.14),
    ("GET", "/api/v1/orders/{id}", 0.10),
    ("POST", "/api/v1/orders", 0.08),
    ("POST", "/api/v1/auth/login", 0.09),
    ("POST", "/api/v1/auth/refresh", 0.05),
    ("GET", "/api/v1/users/{id}", 0.07),
    ("PUT", "/api/v1/users/{id}", 0.03),
    ("GET", "/api/v1/search", 0.11),
    ("POST", "/api/v1/payments", 0.06),
    ("GET", "/health", 0.05),
    ("DELETE", "/api/v1/orders/{id}", 0.04),
)

USER_AGENTS: Final[tuple[str, ...]] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5)"
    " AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "okhttp/4.12.0",
    "Go-http-client/2.0",
)

SCANNER_AGENTS: Final[tuple[str, ...]] = (
    "sqlmap/1.8#stable (https://sqlmap.org)",
    "Nikto/2.5.0",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "python-requests/2.32.3",
    "masscan/1.3",
)

SCAN_PATHS: Final[tuple[str, ...]] = (
    "/.env",
    "/.git/config",
    "/wp-admin/setup-config.php",
    "/phpmyadmin/index.php",
    "/admin",
    "/actuator/env",
    "/api/v1/../../etc/passwd",
    "/config.json",
    "/backup.sql",
    "/.aws/credentials",
)

ERROR_MESSAGES: Final[tuple[str, ...]] = (
    "database connection failed",
    "upstream timed out while reading response header",
    "failed to acquire connection from pool",
    "unhandled exception in request handler",
    "payment provider returned an unexpected status",
    "cache backend unreachable",
    "deadlock detected while updating inventory",
)

INFO_MESSAGES: Final[tuple[str, ...]] = (
    "request completed",
    "cache hit",
    "order created",
    "user session refreshed",
    "background job scheduled",
    "configuration reloaded",
)

#: RFC 5737 documentation ranges — safe to publish, never routed.
_DOC_PREFIXES: Final[tuple[str, ...]] = ("192.0.2.", "198.51.100.", "203.0.113.")

#: The credential values an application might carelessly log.  Fabricated, and
#: kept here as the single definition so that anything asserting "this never
#: reached storage" greps for the same strings the generator actually wrote.
INJECTED_CREDENTIAL_VALUES: Final[tuple[str, ...]] = (
    "eyJhbGciOiJIUzI1NiJ9",
    "Sup3rS3cret!",
    "sk_live_1234567890abcdefghij",
    "someone@example.test",
)

_CREDENTIAL_TEMPLATES: Final[tuple[str, ...]] = (
    "Authorization: Bearer {}.eyJzdWIiOiIxIn0.aaaaaaaaaaaaaaaaaaaa",
    "password={}",
    "api_key={}",
    "user={}",
)

#: The full fragments appended to a message.  Built from the values above, so
#: every value is guaranteed to be a substring of what was written.
INJECTED_CREDENTIALS: Final[tuple[str, ...]] = tuple(
    template.format(value)
    for template, value in zip(_CREDENTIAL_TEMPLATES, INJECTED_CREDENTIAL_VALUES, strict=True)
)


@dataclass(slots=True)
class GeneratorConfig:
    """Knobs for a synthetic dataset."""

    count: int = 100_000
    start: datetime | None = None
    duration: timedelta = timedelta(hours=24)
    fmt: str = "json"  # json | access | plaintext | csv | mixed
    seed: int = 1337
    error_rate: float = 0.04
    malformed_rate: float = 0.01
    duplicate_rate: float = 0.02
    invalid_timestamp_rate: float = 0.003
    services: Sequence[str] = SERVICES
    #: Injected incidents, as fractions through the window.
    error_spikes: Sequence[float] = (0.35, 0.72)
    traffic_spikes: Sequence[float] = (0.55,)
    latency_incidents: Sequence[float] = (0.6,)
    brute_force_attacks: int = 3
    scanning_attacks: int = 2
    include_secrets: bool = True
    #: Credential-bearing records placed at fixed positions, cycling through
    #: :data:`INJECTED_CREDENTIALS` so each value appears.  ``include_secrets``
    #: alone is a ~0.1 % coin flip, which can come up zero on a small dataset;
    #: a check that must prove redaction happened needs a guaranteed floor.
    credential_records: int = 0
    unique_ips: int = 400
    extra: dict[str, Any] = field(default_factory=dict)


class LogGenerator:
    """Deterministic generator of realistic log records."""

    def __init__(self, config: GeneratorConfig | None = None) -> None:
        self.config = config or GeneratorConfig()
        # Seeded PRNG: same seed, same dataset — benchmarks stay comparable.
        self.random = random.Random(self.config.seed)  # noqa: S311 - fake data only  # nosec B311
        self.start = self.config.start or (utcnow() - self.config.duration)
        self._ips = [self._make_ip() for _ in range(max(10, self.config.unique_ips))]
        self._attackers = [self._make_ip() for _ in range(8)]
        self._weights = [weight for _, _, weight in ENDPOINTS]

    # -- primitives ---------------------------------------------------------- #
    def _make_ip(self) -> str:
        prefix = self.random.choice(_DOC_PREFIXES)
        return f"{prefix}{self.random.randint(1, 254)}"

    def _traffic_weight(self, progress: float) -> float:
        """Diurnal curve: quiet at night, two daytime peaks."""
        hour_angle = progress * 2 * math.pi
        return 0.55 + 0.45 * math.sin(hour_angle - math.pi / 2) + 0.15 * math.sin(2 * hour_angle)

    def _timestamp(self, index: int) -> datetime:
        """Non-uniform arrival times shaped by the diurnal curve and spikes."""
        base = index / max(1, self.config.count)
        weight = self._traffic_weight(base)
        for spike in self.config.traffic_spikes:
            if abs(base - spike) < 0.02:
                weight *= 0.25  # events compress in time == higher rate
        offset = self.config.duration.total_seconds() * base * (0.6 + 0.4 * weight)
        jitter = self.random.uniform(-1.0, 1.0)
        return self.start + timedelta(seconds=offset + jitter)

    def _latency(self, progress: float, is_error: bool) -> float:
        """Log-normal latency with an injected degradation window."""
        value = self.random.lognormvariate(3.4, 0.75)  # median ~30 ms
        if is_error:
            value *= self.random.uniform(1.5, 6.0)
        for incident in self.config.latency_incidents:
            if abs(progress - incident) < 0.04:
                value *= self.random.uniform(4.0, 12.0)
        return round(min(value, 60_000.0), 3)

    def _error_probability(self, progress: float) -> float:
        probability = self.config.error_rate
        for spike in self.config.error_spikes:
            if abs(progress - spike) < 0.03:
                probability = min(0.85, probability * self.random.uniform(8, 16))
        return probability

    # -- record construction -------------------------------------------------- #
    def _base_record(self, index: int) -> dict[str, Any]:
        progress = index / max(1, self.config.count)
        timestamp = self._timestamp(index)
        method, endpoint, _ = self.random.choices(ENDPOINTS, weights=self._weights, k=1)[0]
        endpoint = endpoint.replace("{id}", str(self.random.randint(1, 99_999)))
        is_error = self.random.random() < self._error_probability(progress)
        service = self.random.choice(tuple(self.config.services))

        if is_error:
            status = self.random.choices([500, 502, 503, 504, 429], weights=[6, 2, 3, 1, 2])[0]
            level = "ERROR"
            message = self.random.choice(ERROR_MESSAGES)
        elif self.random.random() < 0.06:
            status = self.random.choices([400, 401, 403, 404, 422], weights=[3, 4, 2, 8, 2])[0]
            level = "WARNING"
            message = f"request rejected with {status}"
        else:
            status = self.random.choices([200, 201, 204, 301, 304], weights=[80, 8, 4, 2, 6])[0]
            level = "INFO"
            message = self.random.choice(INFO_MESSAGES)

        return {
            "timestamp": timestamp,
            "level": level,
            "service": service,
            "hostname": self.random.choice(HOSTS),
            "environment": "production",
            "logger": f"{service}.handler",
            "message": message,
            "ip": self.random.choice(self._ips),
            "user_id": f"u_{self.random.randint(1000, 9999)}",
            "request_id": f"{self.random.getrandbits(64):016x}",
            "method": method,
            "path": endpoint,
            "status": status,
            "response_time_ms": self._latency(progress, is_error),
            "bytes": self.random.randint(180, 48_000),
            "user_agent": self.random.choice(USER_AGENTS),
            "referrer": "-" if self.random.random() < 0.7 else "https://example.test/",
        }

    def _attack_records(self) -> list[dict[str, Any]]:
        """Brute-force bursts and endpoint scans at known offsets."""
        records: list[dict[str, Any]] = []
        span = self.config.duration.total_seconds()

        for i in range(self.config.brute_force_attacks):
            attacker = self._attackers[i % len(self._attackers)]
            offset = span * ((i + 1) / (self.config.brute_force_attacks + 1))
            burst = self.random.randint(25, 90)
            for n in range(burst):
                records.append(
                    {
                        "timestamp": self.start + timedelta(seconds=offset + n * 1.7),
                        "level": "WARNING",
                        "service": "auth",
                        "hostname": self.random.choice(HOSTS),
                        "environment": "production",
                        "logger": "auth.login",
                        "message": "authentication failed: invalid credentials",
                        "ip": attacker,
                        "user_id": f"admin{self.random.randint(1, 9)}",
                        "request_id": f"{self.random.getrandbits(64):016x}",
                        "method": "POST",
                        "path": "/api/v1/auth/login",
                        "status": 401,
                        "response_time_ms": round(self.random.uniform(20, 120), 3),
                        "bytes": 220,
                        "user_agent": self.random.choice(SCANNER_AGENTS),
                        "referrer": "-",
                    }
                )

        for i in range(self.config.scanning_attacks):
            attacker = self._attackers[(i + 4) % len(self._attackers)]
            offset = span * ((i + 1) / (self.config.scanning_attacks + 2))
            for n, path in enumerate(
                self.random.choices(SCAN_PATHS, k=self.random.randint(30, 70))
            ):
                records.append(
                    {
                        "timestamp": self.start + timedelta(seconds=offset + n * 0.8),
                        "level": "WARNING",
                        "service": "api-gateway",
                        "hostname": self.random.choice(HOSTS),
                        "environment": "production",
                        "logger": "gateway.router",
                        "message": "route not found",
                        "ip": attacker,
                        "user_id": "-",
                        "request_id": f"{self.random.getrandbits(64):016x}",
                        "method": "GET",
                        "path": path,
                        "status": 404,
                        "response_time_ms": round(self.random.uniform(1, 15), 3),
                        "bytes": 150,
                        "user_agent": self.random.choice(SCANNER_AGENTS),
                        "referrer": "-",
                    }
                )
        return records

    # -- formatting ----------------------------------------------------------- #
    def _as_json(self, record: dict[str, Any]) -> str:
        payload = {
            "timestamp": to_iso(record["timestamp"]),
            "level": record["level"],
            "service": record["service"],
            "host": record["hostname"],
            "env": record["environment"],
            "logger": record["logger"],
            "message": record["message"],
            "client_ip": record["ip"],
            "user_id": record["user_id"],
            "request_id": record["request_id"],
            "http": {
                "method": record["method"],
                "path": record["path"],
                "status": record["status"],
                "duration_ms": record["response_time_ms"],
                "bytes": record["bytes"],
            },
            "user_agent": record["user_agent"],
        }
        return json.dumps(payload, ensure_ascii=False)

    def _as_access(self, record: dict[str, Any]) -> str:
        stamp = record["timestamp"].strftime("%d/%b/%Y:%H:%M:%S +0000")
        user = record["user_id"] if record["user_id"] != "-" else "-"
        return (
            f"{record['ip']} - {user} [{stamp}] "
            f'"{record["method"]} {record["path"]} HTTP/1.1" {record["status"]} {record["bytes"]} '
            f'"{record["referrer"]}" "{record["user_agent"]}" '
            f"{record['response_time_ms'] / 1000:.3f}"
        )

    def _as_plaintext(self, record: dict[str, Any]) -> str:
        stamp = record["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        return (
            f"{stamp} {record['level']} [{record['logger']}] {record['message']} "
            f"status={record['status']} duration={record['response_time_ms']}ms "
            f"request_id={record['request_id']} ip={record['ip']}"
        )

    def _as_csv_row(self, record: dict[str, Any]) -> str:
        return ",".join(
            [
                to_iso(record["timestamp"]),
                record["level"],
                record["service"],
                record["hostname"],
                f'"{record["message"]}"',
                record["ip"],
                record["method"],
                record["path"],
                str(record["status"]),
                str(record["response_time_ms"]),
                str(record["bytes"]),
            ]
        )

    CSV_HEADER: Final[str] = (
        "timestamp,level,service,hostname,message,ip,method,path,status,response_time_ms,bytes"
    )

    def format_record(self, record: dict[str, Any], fmt: str | None = None) -> str:
        chosen = fmt or self.config.fmt
        if chosen == "mixed":
            chosen = self.random.choice(("json", "access", "plaintext"))
        match chosen:
            case "json":
                return self._as_json(record)
            case "access":
                return self._as_access(record)
            case "csv":
                return self._as_csv_row(record)
            case _:
                return self._as_plaintext(record)

    # -- corruption ------------------------------------------------------------ #
    def _corrupt(self, line: str) -> str:
        """Produce a line the parser should reject, in a realistic way."""
        choice = self.random.randint(0, 4)
        if choice == 0:
            return line[: max(1, len(line) // 2)]  # truncated write
        if choice == 1:
            return line.replace('"', "", 1)  # unbalanced quoting
        if choice == 2:
            return "\x00\x01" + line[:80]  # binary garbage from a rotated file
        if choice == 3:
            return "not-a-log-line at all " + str(self.random.random())
        return line + " " + "x" * self.random.randint(100, 400)

    def _with_secret(self, record: dict[str, Any], credential: str | None = None) -> dict[str, Any]:
        """Log a credential — the masking pipeline must catch it."""
        chosen = credential if credential is not None else self.random.choice(INJECTED_CREDENTIALS)
        record = dict(record)
        record["message"] = f"{record['message']} {chosen}"
        return record

    def _credential_positions(self) -> dict[int, str]:
        """Fixed positions for the guaranteed credential-bearing records.

        Spread arithmetically rather than sampled, so asking for them does not
        perturb the PRNG and a given seed still produces the same dataset.
        """
        wanted = min(max(0, self.config.credential_records), self.config.count)
        if wanted == 0:
            return {}
        step = self.config.count / wanted
        return {
            min(self.config.count - 1, int(i * step)): INJECTED_CREDENTIALS[
                i % len(INJECTED_CREDENTIALS)
            ]
            for i in range(wanted)
        }

    # -- iteration -------------------------------------------------------------- #
    def records(self) -> Iterator[dict[str, Any]]:
        """Yield raw record dicts (attacks merged in, chronologically ordered)."""
        attacks = self._attack_records()
        attack_positions = sorted(
            self.random.sample(
                range(self.config.count), k=min(len(attacks), max(1, self.config.count - 1))
            )
        )
        attack_map = dict(zip(attack_positions, attacks, strict=False))
        credentials = self._credential_positions()

        for index in range(self.config.count):
            injected = attack_map.get(index)
            record = injected if injected is not None else self._base_record(index)
            forced = credentials.get(index)
            if forced is not None:
                record = self._with_secret(record, forced)
            elif self.config.include_secrets and self.random.random() < 0.001:
                record = self._with_secret(record)
            if self.random.random() < self.config.invalid_timestamp_rate:
                record = {**record, "timestamp_override": "not-a-timestamp"}
            yield record

    def lines(self, fmt: str | None = None) -> Iterator[str]:
        """Yield formatted log lines, including duplicates and malformed ones."""
        previous: str | None = None
        for record in self.records():
            line = self.format_record(record, fmt)
            if "timestamp_override" in record:
                line = line.replace(to_iso(record["timestamp"]), "not-a-timestamp")
            if self.random.random() < self.config.malformed_rate:
                yield self._corrupt(line)
                continue
            yield line
            if previous is not None and self.random.random() < self.config.duplicate_rate:
                yield previous  # an at-least-once shipper redelivering
            previous = line

    # -- output ----------------------------------------------------------------- #
    def write(self, path: Path, fmt: str | None = None, *, compress: bool | None = None) -> Path:
        """Stream the dataset to a file (gzipped when the name ends in ``.gz``)."""
        ensure_directory(path.parent)
        gzipped = compress if compress is not None else path.suffix.lower() == ".gz"
        chosen = fmt or self.config.fmt

        # The handle is opened here and closed by the ``with`` below; ruff
        # cannot see through the indirection, hence the explicit waivers.
        def open_stream() -> Any:
            if gzipped:
                return gzip.open(  # noqa: SIM115 - closed by the caller's `with`
                    path, "wt", encoding="utf-8", newline="\n", compresslevel=6
                )
            return path.open("w", encoding="utf-8", newline="\n")  # noqa: SIM115 - as above

        with open_stream() as stream:
            if chosen == "csv":
                stream.write(self.CSV_HEADER + "\n")
            for line in self.lines(chosen):
                stream.write(line + "\n")
        return path


def generate_dataset(
    path: Path,
    count: int = 100_000,
    *,
    fmt: str = "json",
    seed: int = 1337,
    duration_hours: float = 24.0,
    **kwargs: Any,
) -> Path:
    """One-call dataset generation, used by the CLI and benchmarks."""
    config = GeneratorConfig(
        count=count,
        fmt=fmt,
        seed=seed,
        duration=timedelta(hours=duration_hours),
        **kwargs,
    )
    return LogGenerator(config).write(path, fmt)


__all__ = [
    "ENDPOINTS",
    "INJECTED_CREDENTIALS",
    "INJECTED_CREDENTIAL_VALUES",
    "SERVICES",
    "GeneratorConfig",
    "LogGenerator",
    "generate_dataset",
]
