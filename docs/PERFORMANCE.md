# Performance

Measured numbers, the method behind them, where the time actually goes, and how
to make it faster.

---

## 1. Reference hardware

Every number below was measured on the development machine. It is deliberately
unflattering — a decade-old dual-core laptop — so the figures are a floor, not a
marketing best case.

| | |
| --- | --- |
| CPU | Intel Core i5-4210U (2 cores / 4 threads, 1.7 GHz base) |
| RAM | 6 GB |
| Disk | SATA SSD |
| OS | Windows 10 (19045) |
| Python | 3.12.5 |
| DuckDB / PyArrow / Polars / pandas | 1.5.5 / 25.0.0 / 1.43.2 / 3.0.3 |

Reproduce with:

```bash
python benchmarks/benchmark.py --records 100000 --output benchmarks/results/run.json
```

A modern server core is roughly 4-6x faster per record than this CPU; scale
accordingly rather than assuming these are the platform's limits.

---

## 2. Headline results — 100 000 JSON records (45.1 MB)

### Ingestion

| Metric | Value |
| --- | --- |
| Wall clock | 88.2 s |
| Throughput | **1,122 records/s** · 0.51 MB/s |
| Output | 11.85 MB Parquet (**3.81x** compression) |
| Peak RSS | ~300 MB (interpreter + PyArrow + buffers) |

### Where the time goes

Each stage timed in isolation over the same records:

| Stage | Throughput | µs/record | Share |
| --- | ---: | ---: | ---: |
| Parse (JSON → validated `LogEvent`) | 3,569 /s | 280 | **44 %** |
| Enrich (masking + derived fields) | 4,175 /s | 240 | **37 %** |
| Normalise (slugs, templating, UA, IP class) | 13,170 /s | 76 | 12 % |
| Clean (control chars, whitespace, mojibake) | 39,458 /s | 25 | 4 % |
| Validate (9 rules) | 74,361 /s | 13 | 2 % |
| Deduplicate (hash + bounded LRU) | 129,910 /s | 8 | 1 % |

Two stages dominate, and both are deliberate costs:

- **Parse** is mostly Pydantic validation (~90 µs) plus the deterministic
  `event_id` fingerprint. Validation is kept because the alternative — trusting
  parser output — moves malformed data past the one component equipped to reject
  it.
- **Enrich** is masking: several regex passes over every text field. This is what
  guarantees no credential is ever written to disk.

Validation and deduplication — the stages people assume are expensive — are
together 3 % of the budget.

### Analytical queries over the resulting dataset

| Engine | Group-by service + count + filtered count + P95 | Throughput |
| --- | ---: | ---: |
| **DuckDB** (streams from Parquet) | **35 ms** | 2.9 M rec/s · 342 MB/s |
| Polars (read into a frame, then aggregate) | 708 ms | 140 k rec/s |
| pandas (read into a frame, then aggregate) | 817 ms | 121 k rec/s |

DuckDB is ~20x faster here because it never materialises the dataset: it reads
only the four columns the query names, pushes the filter into the scan, and
aggregates vectorised. Polars and pandas both pay to build a full in-memory
frame first.

### Platform analytics views

| View | Time |
| --- | ---: |
| `timeseries` (5 m buckets) | 28 ms |
| `services` | 56 ms |
| `traffic` | 95 ms |
| `overview` | 101 ms |
| `errors` (incl. time series) | 116 ms |
| `latency` (incl. per-service and per-endpoint stats) | 168 ms |
| `anomaly_scan` (4 metrics × 2 detectors) | 172 ms |

A full dashboard refresh is roughly 700 ms cold and near-instant warm, because
the API caches these views.

### Streaming

Measured through `loganalytics stream` over a tailed file (3,056 messages,
`max_batch=200`, 50 ms flush interval) on the same machine:

| Metric | Value |
| --- | ---: |
| Throughput | 516 messages/s |
| Flushes | 15 |
| Records queryable within | < 1 s of arrival |

Streaming is slower per record than batch because it flushes ~15x more often —
that is the latency-for-throughput trade the mode exists to make. Run
`loganalytics job run compact` afterwards to merge the small files.

### Authentication

| Path | Cost |
| --- | ---: |
| Warm (cached principal) | 0.005 ms |
| Cold (store reused, no cache) | ~7 ms |
| Before the fix (pool per request + fsync per request) | ~20 ms |

The old behaviour capped the API at ~50 req/s per core on authentication alone.
See `docs/SECURITY.md` for the revocation-latency trade it buys.

### Generation (the control)

The synthetic generator produces 11,389 records/s — itself an indication that
~90 µs of the parse cost is Python object overhead rather than parsing per se.

---

## 3. Memory behaviour

The pipeline is a chain of generators, so peak memory is governed by the storage
batch size, not by input size.

| Input | Records | Added RSS |
| --- | ---: | ---: |
| 5 000 | 5 k | baseline |
| 50 000 | 50 k | **< 150 MB above baseline** |

`tests/performance/test_throughput.py::TestStreamingMemory` asserts this rather
than assuming it: 10x the input must not mean 10x the resident memory. Streaming
100 000 records through `FileSource` alone adds under 80 MB.

Where memory *can* grow, it is bounded on purpose:

| Component | Bound | Consequence of the bound |
| --- | --- | --- |
| Deduplication | `max_tracked_keys` (default 1 M ≈ 120 MB) | Duplicates separated by more than that many records are not detected |
| Parquet writer | `write_batch_size` × partitions | Larger batches = better compression, higher peak |
| Dead-letter queue | `max_records` (1 M) | Counters stay exact; the file is capped |
| Cache | `max_entries` LRU | Oldest entries evicted |
| Rate limiter | LRU bucket map | Idle clients forgotten |
| DuckDB | `memory_limit` with disk spill | Large aggregations get slower, never OOM |

---

## 4. Why each technology

| Choice | Reason | Trade-off accepted |
| --- | --- | --- |
| **Parquet** | Columnar: an analytics query touching 3 of 24 columns reads ~1/8 of the bytes. Row-group statistics let the engine skip data inside a file. Self-describing. Measured 3.8x compression. | Not appendable per record; writes are batched. |
| **zstd** | Better ratio than snappy at similar speed; far faster than gzip to decompress. | Slightly more CPU than snappy on write. |
| **Dictionary encoding** | `level`, `service`, `environment` have tiny cardinality: ~70 % smaller and much faster group-by. | Useless on high-cardinality columns, so it is not applied to them. |
| **DuckDB** | No server; reads Parquet in place; predicate/projection push-down; out-of-core with disk spill; correct SQL including `approx_quantile` and `time_bucket`. | Single-process; not a concurrent OLTP store. |
| **Polars** | Fastest for small in-memory frames and available as an alternative engine. | Materialises the frame. |
| **Pydantic** | The schema is a trust boundary; coercion, bounds and a JSON schema in one declaration. | ~90 µs per record — the largest single cost, paid deliberately. |
| **BLAKE2b** | Faster than SHA-256 in CPython and lets us choose a 128-bit digest. | Not a standard "file checksum" people expect; documented. |
| **Processes for parsing** | Parsing is CPU-bound and GIL-serialised. | ~40 MB per worker; per-worker dedup state. |
| **Threads for jobs** | Jobs are I/O-bound; DuckDB and PyArrow release the GIL. | No CPU parallelism — which those jobs do not need. |

---

## 5. Partition pruning

The single largest query optimisation is structural, not algorithmic.

```
processed/year=2026/month=08/day=07/part-<run>.parquet
```

A query for one day resolves to one directory. `tests/performance` verifies it
against a 60-day dataset: `glob_for_range()` returns 60 globs for the full range
and **1** for a single day, and the scan reads exactly that day's 200 records.

On a year of daily logs this is a 365x I/O reduction — the difference between a
dashboard that answers in 200 ms and one that answers in a minute.

Granularity is a trade-off against the small-files problem: too fine and per-file
metadata dominates. Daily is the default; hourly is available for very
high-volume deployments, and `loganalytics job run compact` merges small files
after streaming ingestion.

---

## 6. Scaling guidance

### Estimating a run

```
seconds ≈ records / (1_100 × effective_workers)      # on the reference CPU
        ≈ records / (5_000 × effective_workers)      # on a modern server core
```

`effective_workers = min(configured, files, cpu_count - 1)` — parallelism is
per-file, so a single 10 GB file does not benefit. Split it first:

```bash
split -l 5000000 huge.log chunk-
loganalytics process --input ./chunks -w 8
```

### Tuning by symptom

| Symptom | Change |
| --- | --- |
| Ingestion CPU-bound | More workers (up to `cpu_count - 1`); split large files |
| Peak memory too high | Lower `storage.write_batch_size`; lower `deduplication.max_tracked_keys` |
| Too many small Parquet files | Raise `write_batch_size`; run the `compact` job; consider daily instead of hourly partitions |
| Queries slow | Ensure the time range is narrow (pruning); raise DuckDB `memory_limit`; compact |
| Dashboard slow | Enable the Redis cache; raise `cache.default_ttl_seconds` |
| Masking is the bottleneck | Trim `masking.rules` to what your data actually contains; set `mask_raw_message: false` (documented risk: the raw line is then stored unredacted) |
| Parsing is the bottleneck | Pass `--format` to skip detection; prefer JSON over regex-parsed text |

### Storage estimates

Based on the measured 3.81x compression of realistic JSON logs:

| Volume/day | Raw | Parquet/day | Parquet/year |
| --- | ---: | ---: | ---: |
| 1 M records | ~450 MB | ~120 MB | ~43 GB |
| 10 M records | ~4.5 GB | ~1.2 GB | ~430 GB |
| 100 M records | ~45 GB | ~12 GB | ~4.3 TB |

Dropping `raw_message` (`RecordEnricher(drop_raw_message=True)`) removes roughly
60 % of stored bytes at the cost of forensic fidelity.

---

## 7. Where the remaining headroom is

Honest assessment of what would move the needle, in order:

1. **Skip re-validation for trusted parsers** (~90 µs/record, ~30 % of ingest).
   `LogEvent.model_construct` bypasses Pydantic. Rejected so far because it moves
   malformed data past the component designed to catch it; a per-source
   `trusted: true` flag would be the honest way to offer it.
2. **Vectorise the transformation stages.** Cleaning, normalisation and masking
   are per-record Python. Batching them into Arrow arrays and applying
   vectorised string kernels would cut the middle of the pipeline substantially,
   at the cost of a much more complex implementation.
3. **Compile the masking rules into one automaton.** The substring pre-filter
   already skips most lines; an Aho-Corasick pass would remove the rest of the
   per-line regex cost.
4. **`orjson` for the JSON parser** — roughly 3x faster than the stdlib decoder,
   at the cost of a compiled dependency.

None of these are implemented, because the current profile shows the platform is
storage- and correctness-dominated rather than throughput-dominated for its
target workload, and each optimisation trades away a property the project values
more.

---

## 8. Running the benchmarks

```bash
# Full benchmark with engine comparison
python benchmarks/benchmark.py --records 1000000

# A specific format, in parallel, results to JSON
python benchmarks/benchmark.py --records 500000 --format access --workers 4 \
    --output benchmarks/results/access-500k.json

# The property-based performance tests (memory flatness, no quadratic growth)
pytest -m performance -v
```

The benchmark uses a seeded generator, so runs are comparable across machines
and commits. Memory is reported as an RSS delta — a floor, not a peak — and is
labelled as such. CI runs a 50 k-record benchmark on every pull request and keeps
the JSON as an artefact, so a regression shows up as a number rather than a
feeling.
