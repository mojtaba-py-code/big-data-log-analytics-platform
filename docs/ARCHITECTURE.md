# Architecture

How the platform is put together, and why each boundary is where it is.

---

## 1. Layering

Dependencies point **inwards**. A layer may import from the layers below it and
never from the ones above.

```
     ┌──────────────────────────────────────────────────────────┐
  6  │  Interfaces      api/   cli/   dashboard/                 │
     ├──────────────────────────────────────────────────────────┤
  5  │  Services        analytics/  anomaly_detection/  search/  │
     │                  cache/  workers/                         │
     ├──────────────────────────────────────────────────────────┤
  4  │  Pipeline        pipeline/                                │
     ├──────────────────────────────────────────────────────────┤
  3  │  Stages          ingestion/  parsers/  validation/        │
     │                  transformation/  deduplication/  storage/│
     ├──────────────────────────────────────────────────────────┤
  2  │  Domain          models/                                  │
     ├──────────────────────────────────────────────────────────┤
  1  │  Core            core/  (config, logging, masking, paths, │
     │                         hashing, retry, metrics, registry)│
     └──────────────────────────────────────────────────────────┘
```

The rule is mechanically checkable: nothing in `app/core` imports from any other
`app` package. That is what keeps the core independently testable and the layers
above it replaceable.

**Consequences of the rule**

- A parser knows nothing about storage, so a new format cannot break a query.
- The analytics engine knows nothing about HTTP, so the CLI and the API compute
  identical numbers — they call the same object.
- The pipeline knows only interfaces, so a new source, format or backend is a
  registration, not an edit.

---

## 2. The canonical schema

Every source, format and parser converges on one Pydantic model,
`app.models.log_event.LogEvent` — 24 fields covering identity, provenance,
payload and request context, plus a bounded `metadata` dict for whatever a source
emits that the schema does not name.

Two properties matter more than the field list.

**Determinism.** `event_id` is a BLAKE2b-128 fingerprint of the record's
identifying content — timestamp, source, service, level, message, request id —
and deliberately *excludes* `ingested_at`. Re-ingesting the same file produces
the same ids, which is what makes the whole pipeline idempotent: a re-run after a
crash overwrites rather than duplicates.

**Optionality.** Everything except `timestamp` is optional. A plain-text
application log has no status code; an Nginx access log has no logger. Requiring
the union of all sources to be complete would reject most real input.

Validation costs roughly 90 µs per record on the reference machine and is the
single most expensive step. It is kept deliberately: the alternative — trusting
parser output — moves malformed data past the one component equipped to reject
it.

---

## 3. The pipeline is a chain of generators

```python
events = self._stage_parse(source, parser, context, dlq, result, opts, stop)
events = self._stage_transform(events, transformer, dlq, result)
events = self._stage_validate(events, validator, dlq, result)
events = self._stage_dedup(events, deduplicator, dlq, result)
store.write(events, run_id=opts.run_id)
```

Nothing between the source and the writer holds more than one record. Peak memory
is therefore governed by the storage batch size alone, not by input size — the
property that lets the same code run a 5 KB fixture in a unit test and a 40 GB
archive in production.

`tests/performance/test_throughput.py` asserts this rather than assuming it:
10x the input must not mean 10x the resident memory.

### Stage order, and why it is that order

| # | Stage | Why here |
| --- | --- | --- |
| 1 | **Parse** | Turns a line into a record. Failures are per-record and expected. |
| 2 | **Clean** | Repairs recoverable damage (control characters, mojibake, whitespace) *before* validation, so records are not rejected for problems the platform can fix. |
| 3 | **Normalise** | Makes records comparable: service slugs, endpoint templating, UA family, IP class. |
| 4 | **Enrich** | Masks secrets and attaches derived attributes. Runs **after** cleaning: if masking ran first, a secret split by an escaped newline could evade the patterns and then be repaired into plaintext. |
| 5 | **Validate** | Decides keep-or-reject. Pure predicate, never mutates. |
| 6 | **Deduplicate** | Last, so it compares fully normalised records. |
| 7 | **Store** | Batched, partitioned, atomically published. |

Cleaning and validation are separate classes on purpose: a cleaner is a pure
function and a validator is a pure predicate, and each is trivially testable
alone. Merging them produces the familiar mess where "repair" and "reject" logic
are interleaved and neither can be reasoned about.

### Failure policy

- A bad **record** never fails a **run**. It is dead-lettered with a
  machine-readable reason, and processing continues.
- If the rejection rate crosses `processing.error_threshold` (checked after a
  meaningful sample), the run **aborts** — that pattern means the format guess or
  the source itself is wrong, and continuing would write millions of garbage rows.
- SIGINT/SIGTERM triggers a **graceful stop**: the current record finishes, the
  writers flush and atomically rename their temporary files, and the partial
  result is reported. A killed run leaves a consistent dataset.

---

## 4. Nothing is silently dropped

Everything that cannot become a `LogEvent` becomes a `RejectedRecord` in the
dead-letter queue: the reason (a closed vocabulary, so the rejection dashboard is
meaningful), the stage, the source, the line number, and the original line —
**masked**, because a malformed record is still log data and may contain the very
credential that malformed it.

The DLQ is JSONL, not Parquet: rejections are written incrementally and read
rarely, so a columnar format would buy nothing and complicate append-on-crash
semantics. It is bounded (`max_records`) while the *counters* stay exact, so the
run summary is truthful even when the file is capped.

Fixed a parser? `replay_rejected()` re-feeds the stored lines. Transient
categories replay by default; deterministic ones (`unparseable`) must be asked
for explicitly, because replaying them unchanged just rejects them again.

---

## 5. Storage

### Layers

```
data/
├── raw/         original lines, as received
├── processed/   normalised LogEvents, the analytics source of truth
├── analytics/   materialised aggregates
└── rejected/    the dead-letter queue
```

### Physical format

Parquet with zstd and dictionary encoding, under an **explicit Arrow schema**.
Letting Arrow infer types per batch is the classic way to produce an unreadable
dataset: one batch where every `status_code` is null infers `null`, the next
infers `int64`, and the two files can no longer be scanned together.

Type choices are deliberate: `timestamp[us, UTC]` because microseconds are what
logs carry and an explicit timezone stops readers guessing; `dictionary<string>`
for `level`/`service`/`environment` because their cardinality is tiny and
dictionary encoding both shrinks the file and speeds up group-by; `int16` for
`status_code`; and `metadata` as a JSON **string** rather than a struct, so the
Parquet schema stays stable no matter which extra keys a source emits.

Measured: 3.8x compression against JSONL on the reference dataset.

### Partitioning

```
processed/year=2026/month=08/day=07/part-<run>.parquet
```

Partitioning turns a full scan into a directory listing. A query for one day
opens one directory instead of every file ever written — on a year of daily logs
that is a 365x I/O reduction, and it is the difference between a dashboard that
answers in 200 ms and one that answers in a minute. Comparison happens on
directory *names*; no file is opened to prune.

Daily granularity is the default because partitioning trades against the
small-files problem: too fine, and per-file metadata dominates. Hourly is
available for very high-volume deployments, and `loganalytics job run compact`
merges small files after streaming ingestion.

### Crash safety

Writers write to `.part-<run>.parquet.tmp` and `os.replace` on close — atomic on
both POSIX and Windows. Readers glob `*.parquet`, so a partially written file is
invisible and can never corrupt a query result.

### Metadata

Parquet holds the data; SQLite/PostgreSQL holds the *facts about* the data — job
runs, ingest checkpoints and API keys. Small, highly transactional,
read-modify-write: exactly what a relational database is for and what a columnar
file store is not.

---

## 6. Query path

DuckDB reads the partitioned Parquet **in place**. There is no load step.

```
request → search DSL → AST → (predicate, params) → DuckDB → Parquet
                                    │
                          allow-listed identifiers only,
                          every value a bound parameter
```

Why aggregate in SQL rather than Python: pulling rows into Python costs one
object per row — at 10 M records that is minutes of interpreter time and
gigabytes of RAM. DuckDB does the same work vectorised, over columnar data,
touching only the columns the query names, spilling to disk if a group-by
outgrows memory. Measured 2.9 M rec/s against 140 k for Polars and 121 k for
pandas on the same aggregation.

The engine's job is therefore to *compose safe SQL* and shape results, not to
compute.

---

## 7. The search language

The search box is the platform's largest injection surface: user text that must
become a SQL predicate. The design makes injection **structurally impossible**
rather than filtered:

1. The tokenizer recognises a fixed vocabulary; anything else is a syntax error
   the user sees.
2. Field names are resolved against `QUERYABLE_COLUMNS` at parse time.
3. The compiler emits operators from a closed map and `?` placeholders only.
4. Complexity is bounded — node count, nesting depth, value length, `IN` arity —
   so a pathological query cannot become a denial of service.

`GET /logs/search?...&explain=true` returns the compiled predicate and the
parameter count, so the property is observable, not just asserted.

---

## 8. Analytics and detection

`AnalyticsEngine` composes SQL for each view; `AnomalyService` runs several
detectors over the resulting time series and merges their findings.

Multiple detectors run at once because each has a blind spot: a global z-score is
distorted by the very outliers it looks for; a trailing moving average adapts to
trend and seasonality but is blind at the start of a series; IQR is robust but
coarse; EWMA reacts fastest to level shifts. Findings for the same
(metric, bucket, dimension) are collapsed to the strongest, and *agreement is
recorded* — an anomaly found by three independent methods is far less likely to
be noise.

Severity combines statistical strength with operational magnitude. A z-score of 6
on a baseline of 0.1 errors is statistically clean and operationally irrelevant;
requiring both keeps the alert list actionable.

Security analytics runs a fixed set of detections per subject and then
**correlates**: an address that trips brute force *and* endpoint scanning *and*
a scanner user-agent scores higher than any single signal. Every finding carries
its evidence, because a score without evidence cannot be triaged.

Detection only. The platform reports and scores; it never blocks, bans or probes.
That is an operator decision made in a system that owns the network path.

---

## 9. API design

- **Application factory**, not a module-level app: tests build one per
  configuration, and importing the module must not open a DuckDB connection or
  start threads.
- **Middleware order** (outermost first): security headers → body-size limit →
  request context → rate limit → CORS. Headers must wrap everything including
  errors raised deeper in the stack; the request id must exist before anything
  logs; a rate-limited request must cost nothing.
- **Expensive collaborators are process-level singletons**, keyed by
  configuration — building a DuckDB connection per request would dominate
  response time, and keying by config stops a second app instance being served
  the first one's engine.
- **One error envelope.** Platform exceptions expose `public_message` only;
  their context is logged, never returned. Unexpected exceptions become a generic
  500. Every response carries `request_id`, so a user can quote it and an operator
  can find the detail — debuggable without leaking.

---

## 10. Caching

Keys are `<namespace>:<view>:<blake2b-96 of every argument that changes the
answer>`. The readable prefix keeps `redis-cli --scan` useful for operators; the
hashed tail keeps keys short and free of user-controlled text.

The cache is **never load-bearing**: every Redis call is wrapped so an outage
degrades to a miss, and a circuit breaker stops hammering a dead server. Values
are JSON, never pickle — unpickling from a shared cache is remote code execution
if anything can write to Redis.

Analytics data is append-only, so entries expire by TTL rather than being
invalidated by writes, and an ingest run drops the affected prefixes so a
dashboard is not stale inside the TTL window.

---

## 10a. Streaming

`app/streaming/` reuses the batch stages but schedules them for the opposite
goal.

| | Batch | Streaming |
| --- | --- | --- |
| Optimises for | throughput | latency |
| Flush trigger | buffer full | buffer full **or** age |
| File size | large row-groups | many small files (compacted later) |
| Failure unit | the run | the batch |

**Delivery.** Storage is flushed *before* offsets are acknowledged, so a crash
between the two replays records rather than losing them; deterministic
`event_id` deduplication then collapses the replay. That pairing is what turns
at-least-once transport into effectively-once storage. Committing first would
be faster and silently lossy on every restart.

**Back-pressure.** The processor pulls and never buffers more than `max_batch`,
so a producer that outruns it is slowed by the consumer not polling — not by
this process growing until the kernel kills it.

**Live window.** A bounded deque of recent events answers "the last five
minutes" without a storage scan; the newest records may not be flushed yet, and
scanning per second is far too expensive. It is bounded by age *and* count,
because age alone still grows without limit during a burst.

**Flush naming.** Each flush writes a distinct file (`pid` + timestamp +
monotonic counter). An earlier version used only a wall-clock second; two
flushes inside the same second overwrote each other and silently lost records.
There is a regression test for exactly that.

**Testability.** The processor consumes any iterable, so the whole path —
including the offset-ordering contract, via a fake consumer — is tested without
a broker running.

---

## 11. Concurrency model

| Workload | Mechanism | Why |
| --- | --- | --- |
| Batch parsing | **Processes** (`ProcessPoolExecutor`) | CPU-bound and GIL-serialised. One file per worker: no shared state, no locks, separate output files, and a crashed worker loses one file rather than the run. |
| Background jobs | **Threads** | Dominated by I/O; DuckDB and pyarrow release the GIL during their heavy work. |
| API | **asyncio** | Request handling is I/O; the query engine parallelises internally. |

The trade-off is documented rather than hidden: per-worker dedup state means
duplicates *spanning two files* are not detected in a parallel run. Use
`--workers 1` when cross-file exactness matters, or the `event_id` strategy and
let deterministic ids collapse duplicates at query time.

Worker count is `min(configured, file_count, cpu_count - 1)` — never more workers
than work, and never every core.

---

## 12. Extension points

Every one is a `Registry`; adding a capability is a registration, never an edit
to a dispatch chain (open/closed).

| Registry | Adds |
| --- | --- |
| `parser_registry` | a log format |
| `source_registry` | an input |
| `storage_registry` | a physical format |
| `dedup_registry` | an identity rule |
| `anomaly_registry` | a detector |
| `cache_registry` | a cache backend |
| `register_job` | a background job |

Registration is **explicit**. There is deliberately no "scan the filesystem and
import whatever looks like a plugin" mode: arbitrary module import driven by data
is remote code execution waiting to happen.

---

## 13. Principles applied

| Principle | Where it shows |
| --- | --- |
| Single responsibility | Cleaner repairs, validator judges, enricher redacts — three classes, three test shapes. |
| Open/closed | Seven registries; no `if format == ...` anywhere. |
| Liskov | Every `StorageBackend` honours the same write/flush/read contract; the pipeline never type-checks. |
| Interface segregation | `LogSource` is `read()` plus optional hints; a database source implements no file methods. |
| Dependency inversion | The pipeline depends on `LogParser`/`StorageBackend`, never on JSON or Parquet. |
| Separation of concerns | Layer rule enforced by the import direction. |
| Configuration-driven | Every threshold, window, limit and rule set is a setting. |
| Fail-safe | Bad records are dead-lettered; bad runs abort; signals stop gracefully. |
| Idempotency | Deterministic ids and run-scoped filenames. |
| Observability | Structured logs, per-stage metrics, run history, DLQ reasons. |
| Testability | 604 tests; every stage constructible in isolation. |
