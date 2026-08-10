# Contributing

---

## Setup

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,postgres,api]"
pytest -q
```

Everything runs without external services: the default configuration uses SQLite
and an in-memory cache, and `fakeredis` covers the Redis paths.

---

## Before you push

```bash
ruff check app tests
ruff format app tests
mypy app                          # --strict, must be clean
pytest -m "not slow"              # the full fast suite
bandit -c pyproject.toml -r app
```

Or in one line:

```bash
make check
```

CI runs exactly these, plus integration tests against real PostgreSQL and Redis,
`pip-audit`, the performance suite and a container build.

---

## The bar

This project holds a few rules more strictly than most. They are what the
codebase is *for*.

### 1. Never silently discard data

If a record cannot be processed, it goes to the dead-letter queue with a reason
from `RejectReason` and enough context to reproduce and replay it. `except:
pass` around a record is a defect, not a shortcut.

### 2. Never load a dataset into memory

Sources return iterators. Stages are generators. If you write
`list(source.read())` outside a test, the change will be rejected — it breaks the
one property that lets this run on files larger than RAM.

### 3. Every external value is a bound parameter

Identifiers may be interpolated **only** after passing an allow-list. If you find
yourself building SQL with an f-string over user input, stop: the search
compiler already solves that problem safely.

### 4. Secrets never reach disk, logs or responses

New fields that can carry user content go through the masker. New error paths
expose `public_message` only. If you add a credential to configuration, it is a
`SecretStr`.

### 5. Bound everything

Every buffer, cache, queue, regex quantifier and result set has a documented
limit. "It will never be that big" is how a service falls over.

### 6. Explain *why*, not *what*

Comments and docstrings should say why a decision was made and what it trades
away. The code already says what it does.

```python
# Good
# ``<=``, not ``<``: with a zero TTL the deadline equals the write time, and on
# a coarse clock (Windows, ~15 ms) a strict comparison would serve an entry that
# was asked to expire immediately.

# Bad
# Check if expired
```

---

## Adding a component

Each extension point is a registry — adding a capability is a registration, not
an edit to a dispatch chain.

### A log format

```python
# app/parsers/my_format.py
from app.parsers.base import LogParser, ParseContext, parser_registry

@parser_registry.register("my-format", "myfmt")
class MyFormatParser(LogParser):
    """One-line description; it appears in `loganalytics plugins`."""

    name = "my-format"
    confidence = 80          # higher beats the catch-all plain-text parser
    extensions = (".mylog",)

    def can_parse(self, sample: Sequence[str]) -> bool:
        """Cheap heuristic. Must never raise."""

    def parse(self, raw: str, context: ParseContext) -> LogEvent:
        """Return a LogEvent or raise ParseError (which dead-letters the line)."""
        fields = {...}
        return self._finalize(fields, raw, context)
```

Then import it in `app/parsers/__init__.py` and add tests: happy path, a
malformed line, and any field-coercion edge case. Use bounded quantifiers in
every pattern.

*No code needed for a one-off text format* — declare a regex in configuration
(`app/parsers/custom.py`).

### Other extension points

| Add | Base class | Registry |
| --- | --- | --- |
| An input | `LogSource` | `source_registry` |
| A storage format | `StorageBackend` | `storage_registry` |
| A dedup rule | `DeduplicationStrategy` | `dedup_registry` |
| An anomaly detector | `AnomalyDetector` | `anomaly_registry` |
| A cache backend | `CacheBackend` | `cache_registry` |
| A background job | plain function | `@register_job("name")` |

A new source must stream. A new storage backend must publish files atomically.
A new detector must be directional-aware (a *drop* in errors is good news).

### An API endpoint

Put it in the right router, declare its scope, use the shared `TimeRangeParams`,
`PaginationParams` and `FilterParams` dependencies, and return a Pydantic model
so the OpenAPI schema stays accurate. Add tests for the happy path, an invalid
parameter and the authorisation boundary.

---

## Tests

| Suite | Marker | Rule |
| --- | --- | --- |
| `tests/unit` | `unit` | No I/O, no network, milliseconds. |
| `tests/integration` | `integration` | Real Parquet, DuckDB, SQLite, FastAPI — all under `tmp_path`. |
| `tests/security` | `security` | One test per control. A failure is a vulnerability. |
| `tests/performance` | `performance`, `slow` | Assert *properties* (memory flat, no quadratic growth), never wall-clock thresholds — those fail on a slow CI runner and pass on a fast laptop while hiding a real regression. |

Test names read as statements of behaviour:

```python
def test_future_timestamp_is_rejected(self) -> None: ...
def test_secrets_are_masked_before_storage(self) -> None: ...
def test_forwarded_for_is_ignored_without_a_trusted_proxy(self) -> None: ...
```

Use the fixtures in `conftest.py` (`settings`, `sample_events`, `populated_store`,
`api_client`, `log_file`) rather than building the world again. Never depend on
the developer's environment: the autouse fixture strips `LOGA_*` variables for
exactly that reason.

New code needs tests. New *security-relevant* code needs a test in
`tests/security` that fails without the fix.

---

## Commits and pull requests

```
<area>: <imperative summary>

Why the change is needed, and what it trades away.
```

```
parsers: infer duration units from the field name

Guessing from magnitude turned `duration_ms=12.5` into 12.5 seconds, a 1000x
error that silently corrupted every latency percentile. The unit now comes from
the value's suffix, then the field name, and only then from magnitude.
```

A pull request should say what changed, why, how it was verified, and what it
does to performance or security if anything. Keep it focused — one concern per
PR.

---

## Project layout

See [ARCHITECTURE.md](ARCHITECTURE.md). The one rule to keep in mind:
**dependencies point inwards**. `app/core` imports from nothing else in `app`;
a stage may not import from the pipeline; the pipeline may not import from the
API. If a change needs to break that, the design is wrong somewhere else.
