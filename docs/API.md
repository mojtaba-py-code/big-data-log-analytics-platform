# API reference

Base URL: `http://localhost:8000` · Interactive schema: `/docs` (development only)

---

## Authentication

Send an API key in either header:

```bash
curl -H "X-API-Key: $LOGA_KEY" http://localhost:8000/logs
curl -H "Authorization: Bearer $LOGA_KEY" http://localhost:8000/logs
```

Mint one:

```bash
loganalytics apikey create dashboard --scopes read
loganalytics apikey create ci --scopes read,write
```

The plaintext is shown **once**; only its SHA-256 hash is stored.

Verified principals are cached for 30 seconds, so revoking a key directly in the
database takes up to that long to bite. `DELETE /admin/apikeys/{name}` clears the
cache immediately.

| Scope | Grants |
| --- | --- |
| `read` | Every query endpoint |
| `write` | `read` + submitting and cancelling jobs |
| `admin` | Everything, including configuration, API keys and destructive jobs |

`/health*` and `/metrics` are unauthenticated — a probe has no credentials — and
therefore expose no configuration.

---

## Conventions

### Time windows

Every analytics endpoint accepts either an explicit range or a rolling window:

| Parameter | Type | Meaning |
| --- | --- | --- |
| `start` | ISO-8601 | Inclusive start (UTC) |
| `end` | ISO-8601 | Inclusive end (UTC) |
| `hours` | float | Window ending now, used when `start`/`end` are absent |

Default: the last 24 hours. Timestamps are always returned as UTC with a
trailing `Z`.

### Filters

Shared by `/logs` and every analytics view: `service`, `level`, `hostname`,
`environment`, `status_code`, `endpoint`, `ip_address`.

### Pagination

`page` (from 1) and `page_size` (clamped to `api.max_page_size`, default 1000).
Responses carry:

```json
{"pagination": {"page": 1, "page_size": 50, "total": 12043, "pages": 241, "has_more": true}}
```

### Errors

One envelope for every failure:

```json
{"error": {"code": "search_syntax_error",
           "message": "unknown field 'password'; searchable fields: ...",
           "request_id": "9f2c1e40a1b24c3d"}}
```

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `bad_request`, `search_syntax_error`, `query_error`, `path_traversal` | Malformed input |
| 401 | `unauthenticated` | Missing or invalid API key |
| 403 | `forbidden` | Insufficient scope |
| 404 | `not_found` | No such record, report or job |
| 409 | `conflict` | Job already running or finished |
| 413 | `payload_too_large` | Body above `api.max_request_bytes` |
| 422 | `validation_error` | Parameter failed validation (includes `details`) |
| 429 | `rate_limited` | Bucket empty (includes `Retry-After`) |
| 500 | `internal_error` | Quote the `request_id` |
| 503 | `service_unavailable` | Storage backend unreachable |

### Response headers

`X-Request-ID`, `X-Response-Time-ms`, `X-RateLimit-Limit`,
`X-RateLimit-Remaining`, plus the security headers described in
[SECURITY.md](SECURITY.md).

---

## Health and metrics

### `GET /health/live`

Liveness. Touches no dependency — if it returns, the process is alive.

```json
{"status": "alive", "uptime_seconds": 1284.3}
```

### `GET /health/ready`

Readiness. Checks storage and cache; returns `503` when storage is unreachable.
A degraded cache does **not** fail readiness — the cache is not load-bearing.

```json
{"status": "ready", "checks": {"storage": "ok", "cache": "ok"}}
```

### `GET /health`

Human-facing summary with component detail, version, environment and the
dataset's first/last event.

### `GET /metrics`

Prometheus text exposition: request counts, failures, durations, cache hit rate
and process memory.

### `GET /stats`

Dataset size and shape.

```json
{"records": 1043221, "services": 9,
 "first_event": "2026-08-06T00:00:03Z", "last_event": "2026-08-07T23:59:58Z",
 "levels": ["DEBUG", "ERROR", "INFO", "WARNING"]}
```

---

## Logs

### `GET /logs`

Filtered, sorted, paginated records.

| Parameter | Default | Notes |
| --- | --- | --- |
| `sort_by` | `timestamp` | Any queryable column |
| `sort_order` | `desc` | `asc` or `desc` |

```bash
curl -H "X-API-Key: $KEY" \
  'localhost:8000/logs?level=ERROR&service=payment&hours=6&page_size=20'
```

### `GET /logs/search`

The full query language.

```
service=payment AND level=ERROR
status_code>=500 AND NOT endpoint~/health
level=ERROR,CRITICAL                       implicit IN
endpoint~/api/v1/*                         wildcard
ip=192.0.2.5 "connection refused"          field + free text
(service=api OR service=auth) AND status>=400
timestamp>2026-08-07T00:00:00Z
```

| Operator | Meaning |
| --- | --- |
| `=` `:` `==` | equals (or `IN` with a comma-separated list) |
| `!=` `<>` | not equals |
| `>` `>=` `<` `<=` | comparison (numeric and timestamp columns) |
| `~` | contains / wildcard (`*`) |
| `AND` `OR` `NOT` | boolean; adjacent terms are implicitly `AND` |
| `( )` | grouping |
| `"..."` | quoted value or free-text phrase |

Field aliases: `ip`, `status`, `path`, `url`, `method`, `host`, `duration`,
`latency`, `time`, `msg`, `app`, `user`, `bytes`, `ua`, `severity`.

Add `explain=true` to see the compiled predicate instead of results:

```json
{"explain": {"query": "service=payment", "predicate": "service = ?", "parameters": 1}}
```

Limits: 4096 characters, 64 terms, 8 nesting levels, 512 characters per value,
50 values per list. Exceeding any of them is a `400`.

### `GET /logs/{event_id}`

One record by its deterministic id. `404` when absent.

### `GET /logs/fields` · `GET /logs/fields/{field}/values`

The searchable-field allow-list and its aliases; value suggestions with an
optional `prefix` for building filter menus.

### `GET /logs/export/stream`

Streams matching records as NDJSON (`application/x-ndjson`), up to `limit`
(max 100 000). Streamed rather than assembled, so a large export neither builds
in memory nor makes the client wait.

```bash
curl -H "X-API-Key: $KEY" \
  'localhost:8000/logs/export/stream?q=level%3DERROR&limit=50000' > errors.jsonl
```

---

## Analytics

All accept the time-window and filter parameters. All are cached under a key
derived from every parameter that changes the answer.

### `GET /analytics/overview`

```json
{"time_range": {"start": "...", "end": "..."},
 "total_records": 1043221, "total_requests": 998412, "total_errors": 41233,
 "error_rate": 0.0395, "average_latency_ms": 74.2,
 "p95_latency_ms": 264.0, "p99_latency_ms": 680.0,
 "active_services": 9, "suspicious_events": 0, "anomalies": 0}
```

### `GET /analytics/errors`

Totals plus breakdowns by service, endpoint, host and level, and an error time
series. Extra parameters: `window` (`1m|5m|15m|1h|6h|1d`), `top` (1-100).

### `GET /analytics/traffic`

Request rates per minute/hour/day, bytes sent, and top IPs, endpoints, user
agents and methods.

### `GET /analytics/latency`

Overall statistics (count, sum, average, min, max, median, P95, P99, stddev)
plus per-service and per-endpoint breakdowns and a P95 time series.

### `GET /analytics/status-codes`

```json
{"total_requests": 998412,
 "by_class": {"2xx": 850120, "3xx": 42001, "4xx": 65058, "5xx": 41233},
 "by_code": [{"key": "200", "count": 812004, "percentage": 81.33}],
 "success_rate": 0.8935, "client_error_rate": 0.0652, "server_error_rate": 0.0413}
```

### `GET /analytics/services`

Per service: requests, errors, failure rate, availability, throughput, latency
statistics and a health status (`healthy` < 2 % failures, `degraded` < 10 %,
`unhealthy` above).

### `GET /analytics/timeseries`

One metric over time, gap-filled. `metric` is one of `requests`, `errors`,
`error_rate`, `server_errors`, `client_errors`, `latency_avg`, `latency_p95`,
`latency_p99`, `latency_max`, `bytes`, `unique_ips`, `unique_users`.

Gap filling matters: an outage produces *no* records, so the bucket is missing
rather than zero, and an unfilled gap draws a flat line straight through the
incident.

### `GET /analytics/anomalies`

```json
{"window": "5m", "metrics": ["errors", "server_errors", "latency_p95", "requests"],
 "count": 7,
 "anomalies": [{"type": "error_spike", "detector": "moving_average+iqr",
                "severity": "critical", "bucket": "2026-08-07T14:30:00Z",
                "metric": "errors", "observed": 423.0, "expected": 4.0,
                "deviation": 419.0, "score": 12.4,
                "description": "423.00 deviates from the 12-bucket trailing average of 4.00 (agreed by 2 detectors)"}]}
```

Parameters: `window`, `metrics` (repeatable), `min_severity`
(`info|low|medium|high|critical`), `limit`.

A `detector` containing `+` means several independent methods agreed — a strong
signal that the finding is not noise.

### `GET /analytics/security`

```json
{"count": 3,
 "findings": [{"type": "credential_stuffing", "severity": "high",
               "risk_score": 89.6, "subject": "198.51.100.48",
               "first_seen": "...", "last_seen": "...", "event_count": 76,
               "evidence": {"attempts": 76, "distinct_users": 76,
                            "correlated_signals": 3},
               "description": "198.51.100.48 failed authentication against 76 distinct accounts"}]}
```

Detections: `brute_force`, `credential_stuffing`, `endpoint_scanning`,
`sensitive_endpoint_access`, `suspicious_user_agent`, `request_flood`,
`secret_in_log`.

### `GET /analytics/windows`

The supported window sizes and metric names — useful for building a UI.

---

## Reports

### `GET /reports/daily` · `GET /reports/summary`

A full report: overview, every analytics section, anomalies and security
findings. `format=json|markdown|html`; `/reports/daily` takes `date`,
`/reports/summary` takes the standard window parameters.

```bash
curl -H "X-API-Key: $KEY" \
  'localhost:8000/reports/daily?date=2026-08-07&format=markdown' > report.md
```

### `GET /reports/stored` · `GET /reports/stored/{name}`

List and fetch reports previously written by the `report` job. Names are
sanitised and re-resolved under the reports directory, so traversal cannot
escape it.

---

## Jobs

### `GET /jobs/available`

```json
{"jobs": ["cleanup", "compact", "detect_anomalies", "generate_data",
          "ingest", "ingest_directory", "report", "security_scan"],
 "admin_only": ["cleanup", "compact"]}
```

Jobs are submitted **by name** from a registry — a request can never schedule
arbitrary code.

### `POST /jobs` — requires `write`

```bash
curl -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"name": "ingest", "parameters": {"source": "/logs/access.log"}}' \
  localhost:8000/jobs
```

```json
{"job": {"id": "a1b2c3d4e5f60718", "name": "ingest", "status": "pending", ...},
 "status_url": "/jobs/a1b2c3d4e5f60718"}
```

Returns `202`. `cleanup` and `compact` additionally require `admin`.

### `GET /jobs` · `GET /jobs/{id}`

Recent jobs (filterable by `status`) and one job's status, attempts, duration and
result summary.

### `DELETE /jobs/{id}` — requires `write`

Cancels a job that has not started. A running job cannot be cancelled:
interrupting a writer mid-flush would leave a partial output file. Returns `409`
if it is already running or finished.

---

## Admin — all require `admin`

| Endpoint | Purpose |
| --- | --- |
| `GET /admin/config` | Effective configuration, every secret redacted |
| `GET /admin/plugins` | Registered parsers, sources, backends, detectors, jobs |
| `GET /admin/runs` | Recent pipeline runs and aggregate statistics |
| `GET /admin/rejected` | Dead-letter counts by reason |
| `GET /admin/cache/stats` · `POST /admin/cache/clear` | Cache inspection and invalidation |
| `POST /admin/reload` | Re-read configuration and rebuild dependencies |
| `GET/POST /admin/apikeys` · `DELETE /admin/apikeys/{name}` | Key management |

`POST /admin/apikeys` returns the plaintext key **once**:

```json
{"name": "dashboard", "scopes": ["read"], "api_key": "…",
 "warning": "This key is shown only once. Store it securely."}
```

---

## Dashboard

`GET /dashboard` — a single self-contained HTML page (see the README). Enter the
API key in the header field; it is kept in `sessionStorage`, so it dies with the
tab.

---

## Rate limiting

A token bucket per credential (falling back to client address), refilling
continuously at `rate_limit_requests / rate_limit_window_seconds` with capacity
`rate_limit_requests + rate_limit_burst`.

```
HTTP/1.1 429 Too Many Requests
Retry-After: 3
X-RateLimit-Limit: 120
X-RateLimit-Remaining: 0
```

Health and metrics endpoints are never throttled.

---

## Python client sketch

```python
import httpx

client = httpx.Client(
    base_url="http://localhost:8000",
    headers={"X-API-Key": "..."},
    timeout=30.0,
)

overview = client.get("/analytics/overview", params={"hours": 24}).json()
print(f"{overview['total_errors']:,} errors ({overview['error_rate']:.2%})")

errors = client.get(
    "/logs/search",
    params={"q": "level=ERROR AND status_code>=500", "page_size": 100},
).json()
for item in errors["items"]:
    print(item["timestamp"], item["service"], item["message"])

for finding in client.get("/analytics/security").json()["findings"]:
    print(finding["subject"], finding["type"], finding["risk_score"])
```
