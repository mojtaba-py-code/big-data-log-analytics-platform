# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- The dashboard's Content-Security-Policy no longer carries `'unsafe-inline'`.
  The stylesheet and the script moved out of the page into same-origin files,
  so `script-src` and `style-src` name `'self'` and nothing else — which is the
  whole point of sending a CSP on a page that renders log text.

### Changed

- The end-to-end demo's "no secrets reached storage" step is a real check: it
  forces credential-bearing records into the dataset, reads storage back
  through the query engine instead of grepping compressed bytes, and exits
  non-zero if a credential survived or the redaction marker is missing.
- The synthetic generator takes `credential_records`, placing a guaranteed
  number of credential-bearing records at deterministic positions. Datasets
  generated with the previous defaults are unchanged, byte for byte.
- MyPy targets Python 3.12, so `mypy app` no longer aborts inside numpy's
  bundled stubs before checking any project code. Ruff still enforces the 3.11
  support floor.

### Fixed

- The clone URL in the README and the Homepage and Documentation links in the
  package metadata pointed at a repository name that does not exist.
- `.env.example` documents `POSTGRES_PASSWORD` and `LOGA_API_KEYS`, without
  which `docker compose up` refuses to start.

### Added

- CI re-runs bandit and pip-audit on a weekly schedule, so a newly published
  advisory against a pinned dependency surfaces without a push.
- `.gitignore` covers PKCS#12 bundles, certificates, SSH private keys and
  `credentials.json`.

## [1.0.0] - 2026-08-14

### Security

- Every GitHub Action is pinned to a full commit SHA and the workflow token is
  scoped to `contents: read`.
- Dependency floors raised off releases with published CVEs.
- A security-reporting policy and vulnerability disclosure process.

### Added

- Badges for CI, coverage, typing, linting and the security scans.
- Dashboard screenshots and the output of a real demo run in the README.

### Changed

- The flat-memory claim replaced with two measured end-to-end runs.

## [1.0] - 2026-08-10

First complete release: a platform that ingests, parses, validates,
normalises, de-duplicates, analyses and serves large volumes of logs.

### Added

- Constant-memory streaming ingestion from files, directories, databases and
  paginated HTTP APIs, with a dead-letter queue so nothing is silently dropped.
- Pluggable parsers for JSON/JSONL, Apache and Nginx access and error logs,
  syslog, logfmt, CSV/TSV, plain text and operator-defined regex formats, with
  format auto-detection.
- A 24-field canonical event schema with a deterministic `event_id` that makes
  re-ingestion idempotent.
- Schema validation and quarantine of malformed records, and cleaning,
  normalisation and enrichment stages including secret masking before storage.
- Four deduplication strategies over a bounded index.
- Hive-partitioned Parquet storage with partition pruning, queried in place by
  DuckDB, behind a swappable `StorageBackend` interface.
- A safe search language compiled to bound SQL parameters.
- Analytics: errors, status distribution, latency percentiles, traffic, top-N,
  per-service health and time-series over six window sizes.
- Statistical anomaly detection (z-score, moving average, IQR, EWMA) and
  security analytics with 0-100 risk scoring.
- A FastAPI REST layer with scoped API-key authentication, rate limiting and
  strict response headers, plus a self-contained operator dashboard.
- A Typer command-line interface for ingestion, query and administration.
- Background workers for scheduled ingestion and compaction.
- A synthetic log generator and an end-to-end demonstration script.
- A benchmark harness for throughput and memory profiling.
- Unit, integration, security and performance test suites.
- A GitHub Actions pipeline covering lint, types, tests, security scanning,
  performance and the container image build.
- A non-root container image and a Compose stack.
- Architecture, API, security, deployment and performance documentation.

### Fixed

- Windows-style path traversal is rejected on POSIX as well.
- `--json` output is left unstyled so it stays machine-parseable.
- The import cycle between `analytics` and `anomaly_detection`.
