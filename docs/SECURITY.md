# Security

Threat model, the controls that answer it, and how each one is verified.

Every control below has a corresponding test in `tests/security/`. A failure
there is a vulnerability, not a style issue.

---

## 1. Threat model

The platform ingests **attacker-influenced data** (log lines are written by
whatever hit your web server), exposes a **query API**, and runs **inside a
network** next to databases and cloud metadata services. That produces five
threat classes:

| # | Threat | Attacker capability | Primary control |
| --- | --- | --- | --- |
| T1 | **Injection** | Controls log content and search input | Allow-listed identifiers + bound parameters |
| T2 | **Data exfiltration** | Steals a backup, a Parquet file or a log line | Masking before storage |
| T3 | **Unauthorised access** | Reaches the API | API keys, scopes, rate limiting |
| T4 | **Server-side request forgery** | Controls an ingestion URL | DNS resolution + address checks on every hop |
| T5 | **Denial of service** | Sends huge, malformed or pathological input | Bounded everything |

Explicitly **out of scope**: TLS termination (use a reverse proxy), network
segmentation, host hardening, and physical security.

---

## 2. T1 — Injection

### 2.1 Search (the largest surface)

`/logs/search?q=...` turns user text into a SQL predicate. Injection is made
*structurally impossible* rather than filtered:

1. **Tokenizer** — recognises a fixed vocabulary. `'` is not a token, so
   `'; DROP TABLE logs; --` fails at position 8 with a syntax error.
2. **Allow-list** — field names resolve against
   `app.models.log_event.QUERYABLE_COLUMNS`. `password=x` is rejected; so is
   `1=1`, because `1` is not a field.
3. **Closed operator map** — the compiler can emit `=`, `<>`, `<`, `<=`, `>`,
   `>=`, `IN`, `ILIKE` and nothing else.
4. **Bound parameters** — every value leaves as `?`. No user byte reaches the
   SQL string, ever.
5. **LIKE escaping** — `%` and `_` in a user term are escaped so a literal `%`
   cannot silently become "match anything".

Observable, not just asserted:

```bash
curl 'localhost:8000/logs/search?q=service=payment&explain=true'
# {"explain": {"query": "service=payment", "predicate": "service = ?", "parameters": 1}}
```

### 2.2 Analytical SQL

Column names interpolated into analytics SQL go through `validate_column()` —
an allow-list, not an escape function.

The **file list is a bound parameter too**: the scan is the constant fragment
`read_parquet(?, ...)` and the pruned globs arrive as a value. Nothing but
allow-listed identifiers is ever interpolated. This was not the original
design — the paths used to be quoted into the SQL text, which meant a data root
containing an apostrophe broke every analytics query. `TestSqlLiteralEscaping`
pins the fix.

The one place a path still reaches SQL text is DuckDB's `SET temp_directory`,
which accepts no bind parameters; there the value is quote-escaped by doubling,
the only correct escaping for a SQL string literal.

> Bandit's `B608` is skipped project-wide (see `pyproject.toml`) because it fires
> on every analytics query for the same reason — an f-string containing a
> validated identifier. The invariant is instead
> enforced by `tests/security/test_security.py::TestSearchInjection`, which
> asserts that no payload fragment appears in the generated SQL and that
> placeholder count equals parameter count — a stronger guarantee than 22
> per-line waivers.

### 2.3 External databases

`DatabaseSource` is the only component that builds SQL for a foreign database.
Identifiers are validated against `^[A-Za-z_][A-Za-z0-9_]{0,62}$` and quoted per
dialect; every filter value is a named bind parameter. The module is
intentionally small enough to audit in full.

### 2.4 Log forging

Control characters and ANSI escapes are stripped from every field on ingest. A
`\r\n` inside a message lets an attacker inject a fake line into any downstream
text renderer; an ANSI escape can rewrite an operator's terminal.

### 2.5 Cross-site scripting

The dashboard inserts every value with `textContent`, never `innerHTML`, and the
API sends `Content-Security-Policy: default-src 'self'` with
`object-src 'none'` and `frame-ancestors 'none'`.

No directive carries `'unsafe-inline'`. The dashboard's stylesheet and script
are separate same-origin files precisely so that `script-src` can stay
`'self'`: with `'unsafe-inline'` the policy would still block a remote payload
but not an injected `<script>` or event-handler attribute, which is the case
that matters on a page rendering attacker-controlled log text.

**Tests:** `TestSearchInjection` (29), `TestDatabaseIdentifierValidation` (9).

---

## 3. T2 — Secret leakage

### 3.1 Masking before storage

`app/core/masking.py` is the single authority on what counts as sensitive.
Redaction happens on **ingest**, so a stolen Parquet file or database backup
contains no credential. This is the only redaction that survives theft.

Detected by default: authorization headers, `key=value` pairs for ~30 sensitive
field names, JWTs, vendor keys (AWS, GitHub, Slack, Stripe, Google), PEM private
key blocks, and e-mail addresses. Opt-in: credit-card numbers and phone numbers
(aggressive — they also match long numeric identifiers).

Masking is applied to the message, the raw line, metadata, user agent, referrer,
endpoint and user id. It is irreversible: no prefix is kept.

Performance note: a substring pre-filter runs before the regexes, so a line with
no trigger token skips them entirely. The trigger sets are supersets of what
their patterns can match — under-triggering would let a secret through, so
`test_trigger_prefilter_does_not_miss_secrets` pins the behaviour.

### 3.2 The dead-letter queue is masked too

A malformed record is still log data and may contain the very credential that
malformed it.

### 3.3 Configuration

Every credential field is a Pydantic `SecretStr`. It renders as `**********` in
`repr`, in `GET /admin/config`, in validation errors, and in the CLI's
`config show`. Credentials have no defaults — a missing password is an error,
never an empty string that silently connects to an unprotected database.

### 3.4 Logging

A `MaskingFilter` sits on the **handler**, not the logger, so records emitted by
third-party libraries (uvicorn, SQLAlchemy) are redacted too. Exception
tracebacks are formatted and *then* masked, which is what catches the classic
leak: a stack trace containing a DSN with an embedded password.

Authentication failures log the client and path, never the presented key.

### 3.5 Errors

Platform exceptions expose only `public_message`; their context — file paths,
SQL fragments, hostnames — is logged, never returned. Unexpected exceptions
become a generic 500. Search syntax errors are the one exception: their message
is safe because it only ever describes the client's own input.

**Tests:** `TestSecretHandling` (10), including one that greps the written Parquet
bytes for the exact credentials the generator injected.

---

## 4. T3 — Authentication, authorisation, rate limiting

### 4.1 Authentication

API keys via `X-API-Key` or `Authorization: Bearer <key>`, compared with
`hmac.compare_digest` against SHA-256 hashes. Constant-time comparison matters:
a short-circuiting `==` leaks the shared prefix length through response latency
and makes key recovery tractable.

Two sources, both active at once:

- `api.api_keys` / `api.api_key_hashes` in configuration — deployment secrets.
  Prefer the hashes so plaintext never touches a config file.
- The metadata store — named keys with scopes and revocation, minted by
  `loganalytics apikey create`. **Stored hashed**; the plaintext is shown once
  and cannot be recovered, so a database leak yields no usable key.

### 4.1a Verification cost

Database-backed verification used to cost ~20 ms per request, because it built a
connection pool per call *and* wrote `last_used_at` — a commit with an fsync —
on every authenticated read. That capped the API at roughly 50 requests per
second per core on nothing but authentication.

Now: one store per database, a 30-second principal cache, and `last_used_at`
written at most once a minute. Warm verification is ~0.005 ms.

The trade is explicit: **revocation takes effect within 30 seconds**, not
instantly. `DELETE /admin/apikeys/{name}` and `POST /admin/reload` clear the
cache immediately, so the window only applies to a key revoked directly in the
database. Failed verifications are never cached — a cached rejection would be a
cheap oracle and would block a newly minted key.

### 4.2 Authorisation

Scopes `read` → `write` → `admin`, where `admin` implies the others. Routes
declare what they need; there is no implicit privilege. Destructive jobs
(`cleanup`, `compact`) require `admin` even for a caller that can submit other
jobs.

With `auth_required=false` (development only — production config validation
refuses it) the anonymous principal holds every scope. A read-only anonymous
principal would make writes impossible rather than merely unauthenticated, which
is a confusing failure rather than a safer one.

### 4.3 Rate limiting

A continuous-refill token bucket per credential, falling back to client address.
Continuous refill rather than a fixed window: a fixed window permits a double-rate
burst across the boundary.

`X-Forwarded-For` is **ignored** unless the immediate peer matches
`api.trusted_proxies`. Trusting it unconditionally lets any client claim any
identity, defeating the limit and poisoning audit logs.

Health and metrics endpoints are exempt: throttling a liveness probe removes a
service from the load balancer exactly when it is already under pressure.

### 4.4 Response hardening

`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, a strict CSP, `Permissions-Policy`,
`Cross-Origin-Opener-Policy`, `Cache-Control: no-store`, optional HSTS, and the
`Server` header removed.

CORS is closed by default; wildcard origins are refused in production.
`allow_credentials` is false — the API uses bearer tokens, not cookies.

**Tests:** `TestAuthentication` (11), `TestAuthorization` (4),
`TestPrincipalCaching` (4), `TestRateLimiting` (6), `TestResponseHardening` (5).

---

## 5. T4 — Path traversal and SSRF

### 5.1 Paths

Every externally supplied path passes through `resolve_within()` before it is
opened:

- resolved and asserted to be a descendant of an allow-listed root;
- symlinks rejected (a link pointing outside fails the containment check anyway);
- NUL bytes rejected;
- Windows reserved device names (`CON`, `NUL`, `COM1`…) rejected — opening them
  hangs or writes to hardware;
- NTFS alternate data streams (`file.log:hidden`) rejected;
- `PermissionError` from a protected path is caught rather than propagated, so
  the containment check is what decides.

Externally supplied *file names* (report names, `Content-Disposition`) go through
`safe_filename()`, which folds separators to underscores and strips leading dots.

Reading roots are configured explicitly (`ingestion.allowed_roots`) and default
to the data root alone.

### 5.2 SSRF

HTTP ingestion is the SSRF surface — the process usually sits inside a private
network next to a cloud metadata service.

1. Scheme allow-list: `http`, `https`. No `file://`, `gopher://`, `ftp://`.
2. DNS is resolved **before connecting** and every resulting address is checked
   against private, loopback, link-local, reserved, multicast and unspecified
   ranges. This blocks `http://169.254.169.254/` and `http://localhost:6379/`
   including via a hostname that resolves to them.
3. Redirects are **not** followed automatically; each hop is re-validated, which
   closes the "public URL redirects to the metadata service" bypass.
4. Response size and time are capped.
5. URLs are logged without their query string — tokens live there.

`ingestion.allow_private_network_sources` exists because pulling from an internal
log API is legitimate. It must be enabled deliberately, and the platform logs
loudly when it is.

**Tests:** `TestPathTraversal` (17), `TestSsrf` (12).

---

## 6. T5 — Denial of service

| Vector | Control |
| --- | --- |
| Unterminated multi-gigabyte "line" | `processing.max_line_bytes`; longer lines are truncated and counted, never buffered |
| Decompression bomb | The *decompressed* stream is capped, not the file |
| Unbounded dedup memory | Bounded LRU; eviction is counted and reported |
| Metadata cardinality explosion | 64 keys, 4 KB per value, enforced by the schema |
| Pathological search | Node count, nesting depth, value length and `IN` arity all bounded |
| ReDoS | Every parser pattern uses bounded, non-nested quantifiers; configured patterns are rejected if they contain a nested unbounded quantifier |
| Oversized request body | Rejected on `Content-Length` before buffering |
| Unbounded result set | Page size clamped; a hard ceiling above that in the engine |
| Runaway aggregation | DuckDB `memory_limit` with disk spill rather than an OOM kill |
| Unbounded rejection files | DLQ capped while counters stay exact |
| Unbounded rate-limiter state | Bucket map is LRU-evicted |

**Tests:** `TestResourceLimits` (6).

---

## 7. Secure defaults

The default configuration is the safe one:

| Setting | Default | Why |
| --- | --- | --- |
| `api.host` | `127.0.0.1` | Binding `0.0.0.0` must be a decision |
| `api.auth_required` | `true` | |
| `api.cors_origins` | `[]` | |
| `api.trusted_proxies` | `[]` | `X-Forwarded-For` ignored until configured |
| `masking.enabled` | `true` | |
| `ingestion.allow_private_network_sources` | `false` | |
| `ingestion.follow_symlinks` | `false` | |
| `deduplication.max_tracked_keys` | 1 M | Bounded, not unbounded |
| `cleanup` job `dry_run` | `true` | A job that deletes data must be asked twice |

### Production refusals

`environment: production` turns advice into enforcement. The process **will not
start** if debug is on, authentication is off, no credentials are configured,
CORS is `*`, masking is off, the log level is `DEBUG`, or docs are enabled.

```bash
loganalytics config validate --environment production
```

The failure mode being prevented is silent: an API deployed with
`auth_required=false` looks perfectly healthy while serving every log line to
the internet.

---

## 8. Supply chain

- Dependencies pinned by lower bound in `pyproject.toml`; CI runs `pip-audit`
  on every push.
- `bandit` on every push.
- The Docker image is multi-stage: the runtime contains no compiler and no
  package-manager cache. It runs as an unprivileged user with `nologin`, declares
  its writable volumes so the root filesystem can be read-only, and CI asserts
  the image does not run as root.
- Celery accepts JSON only. A broker that can deliver pickled payloads is a
  remote-code-execution primitive if anything can write to it.
- The cache stores JSON only, for the same reason.
- CI has `permissions: contents: read` and greps for credential-shaped literals
  in tracked source.

---

## 9. Data protection

- **In transit** — terminate TLS at a reverse proxy (see `docs/DEPLOYMENT.md`).
  Set `api.hsts_enabled` once TLS is in place.
- **At rest** — use encrypted volumes. The platform's contribution is that the
  most sensitive content is already redacted before it is written.
- **Retention** — `loganalytics job run cleanup` deletes partitions older than a
  retention window. It defaults to a dry run and re-checks that the target is
  inside the configured data root before deleting.
- **Least privilege** — the metadata database account needs `SELECT`/`INSERT`/
  `UPDATE` on the metadata schema only; a source database account needs `SELECT`
  on the log table only.

---

## 10. Observability of security events

Every one of these is logged, structured and correlated by request id:
authentication failures (without the key), authorisation denials, rate-limit
hits, path-traversal and SSRF rejections, configuration reloads, and API-key
creation and revocation.

`GET /analytics/security` surfaces detections found *in the ingested logs*:
brute force, credential stuffing, endpoint scanning, sensitive-endpoint access,
scanner user-agents, request floods, and applications that log their own
credentials.

Risk scores combine a per-class base with volume (logarithmic — 10 000 attempts
is worse than 100, but not 100x worse), breadth, correlation across signals, and
whether the source is a public address. False positives are expected and
acknowledged: a load balancer health check, a CI runner or a corporate NAT can
all look like a flood. That is why every finding carries its evidence — a score
without evidence cannot be triaged.

**The platform detects and reports. It never blocks, bans or probes.** Acting on
a finding is an operator decision made in a system that owns the network path.

---

## 11. What is deliberately not done

- **No offensive capability.** No scanning, no probing, no active response.
- **No password hashing.** The platform authenticates services, not humans;
  API keys are high-entropy random values, so SHA-256 is appropriate. Human
  passwords would need Argon2 and are out of scope.
- **No plugin auto-discovery.** Import driven by data is remote code execution
  waiting to happen; registration is explicit.
- **No `eval`, `exec`, `pickle` or shell invocation anywhere in `app/`.**

---

## 12. Reporting a vulnerability

Please report privately rather than opening a public issue. Include a
description, reproduction steps, affected version and any suggested fix.

Verify the controls yourself:

```bash
pytest -m security -v
bandit -c pyproject.toml -r app
pip-audit
```
