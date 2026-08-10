"""Command-line interface.

Design rules
------------
* **Machine-readable and human-readable.**  Every command accepts ``--json``.
  Human output goes through Rich to *stdout*; logs go to *stderr*.  That
  separation is what makes ``loganalytics stats --json | jq`` work.
* **Meaningful exit codes.**  ``0`` success, ``1`` failure, ``2`` invalid
  usage, ``3`` partial success (a run that completed with rejections above the
  warning threshold).  A CI job can branch on these.
* **No hidden state.**  Every command takes ``--config`` and honours the same
  environment variables as the API, so what you test on the CLI is what the
  service does.
"""

import json as json_module
import sys
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from app import __version__
from app.core.config import Settings, load_settings
from app.core.exceptions import LogAnalyticsError
from app.core.logging import configure_from_settings, get_logger
from app.core.timeutil import parse_timestamp, to_iso, utcnow

log = get_logger(__name__)

#: Rich writes to stdout; the logging handler writes to stderr.  Never mix.
console = Console()
error_console = Console(stderr=True)

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_PARTIAL = 3

app = typer.Typer(
    name="loganalytics",
    help="Big Data Log Analytics Platform - ingest, analyse and report on log data.",
    add_completion=True,
    no_args_is_help=True,
    rich_markup_mode="rich",
)


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"
    MARKDOWN = "markdown"


def _settings(config: Path | None = None, overrides: dict[str, Any] | None = None) -> Settings:
    settings = load_settings(config, overrides)
    configure_from_settings(settings)
    return settings


def _write_json(text: str) -> None:
    """Write JSON to stdout unstyled.

    ``Console.print_json`` syntax-highlights what it prints.  Rich normally
    drops the colour when stdout is not a terminal, but anything that forces it
    on — ``FORCE_COLOR=1`` is set by default in many CI images — puts ANSI
    escapes in stdout and ``--json | jq`` then chokes on output that is no
    longer JSON.  Machine-readable output must stay machine-readable.
    """
    sys.stdout.write(text + "\n")


def _emit(payload: Any, as_json: bool, title: str = "") -> None:
    """Print a result either as JSON or as a Rich table."""
    if as_json:
        _write_json(json_module.dumps(payload, default=str, indent=2))
        return
    if isinstance(payload, dict):
        table = Table(title=title or None, show_header=False, box=None, pad_edge=False)
        table.add_column(style="cyan", no_wrap=True)
        table.add_column(style="white")
        for key, value in payload.items():
            table.add_row(str(key), _render(value))
        console.print(table)
    elif isinstance(payload, list) and payload and isinstance(payload[0], dict):
        table = Table(title=title or None, header_style="bold cyan")
        for column in payload[0]:
            table.add_column(str(column))
        for row in payload[:200]:
            table.add_row(*(_render(row.get(column)) for column in payload[0]))
        console.print(table)
    else:
        console.print(payload)


def _render(value: Any) -> str:
    if isinstance(value, bool):  # before int: bool is a subclass of int
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:,.4f}".rstrip("0").rstrip(".")
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in list(value.items())[:8]) or "-"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value[:5]) or "-"
    return "-" if value is None else str(value)


def _fail(message: str, code: int = EXIT_FAILURE) -> None:
    error_console.print(f"[bold red]error:[/bold red] {message}")
    raise typer.Exit(code)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version", help="Show the version and exit.")] = False,
) -> None:
    """Big Data Log Analytics Platform."""
    if version:
        console.print(f"loganalytics {__version__}")
        raise typer.Exit(EXIT_OK)
    if ctx.invoked_subcommand is None:
        # Reached only when the group is invoked without a command *and*
        # without --version; Typer's own no_args_is_help handles the bare
        # case first and exits with the usage code.
        console.print(ctx.get_help())
        raise typer.Exit(EXIT_USAGE)


# --------------------------------------------------------------------------- #
# Ingestion
# --------------------------------------------------------------------------- #
@app.command()
def ingest(
    source: Annotated[str, typer.Argument(help="File, directory, URL or database DSN.")],
    config: Annotated[Path | None, typer.Option("--config", "-c", help="Config file.")] = None,
    fmt: Annotated[str | None, typer.Option("--format", "-f", help="Force a parser.")] = None,
    service: Annotated[
        str | None, typer.Option(help="Service name for records that lack one.")
    ] = None,
    layer: Annotated[str, typer.Option(help="Destination layer.")] = "processed",
    limit: Annotated[int | None, typer.Option(help="Stop after N records.")] = None,
    workers: Annotated[
        int | None, typer.Option("-w", help="Parallel workers (directories only).")
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Parse and validate without writing.")
    ] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Ingest logs from a source into the platform.

    Examples:

      loganalytics ingest server.log

      loganalytics ingest /var/log/nginx --workers 4 --format access
    """
    from app.pipeline import LogPipeline, PipelineOptions, process_parallel

    settings = _settings(config)
    options = PipelineOptions(
        parser=fmt, service=service, layer=layer, limit=limit, dry_run=dry_run
    )
    try:
        path = Path(source)
        if path.is_dir() and (workers or settings.processing.workers) > 1:
            from app.core.paths import iter_files

            files = iter_files(path, follow_symlinks=settings.ingestion.follow_symlinks)
            if not files:
                _fail(f"no matching files under {source}", EXIT_USAGE)
            result = process_parallel(files, settings, options, workers=workers)
        else:
            result = LogPipeline(settings).run(source, options)
    except LogAnalyticsError as exc:
        _fail(str(exc))
        return

    _emit(result.summary(), as_json, title="Ingestion result")
    if not result.succeeded:
        raise typer.Exit(EXIT_FAILURE)
    if result.rejection_rate > 0.05:
        error_console.print(
            f"[yellow]warning:[/yellow] {result.rejection_rate:.1%} of records were rejected"
        )
        raise typer.Exit(EXIT_PARTIAL)


@app.command()
def process(
    input_dir: Annotated[Path, typer.Option("--input", "-i", help="Directory of raw logs.")],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Override the data root.")
    ] = None,
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    workers: Annotated[int | None, typer.Option("-w")] = None,
    pattern: Annotated[str, typer.Option(help="Glob for files to include.")] = "*",
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Batch-process every file in a directory.

    Example: loganalytics process --input data/raw --output data/processed
    """
    from app.core.paths import iter_files
    from app.pipeline import PipelineOptions, process_parallel

    # ``--output data/processed`` names a *layer* directory, so the data root is
    # its parent; anything else is taken as the data root itself.  Guessing
    # silently (always using the parent) sent ``--output /tmp/out`` to
    # ``/tmp/processed``, which is not where anyone looked for it.
    overrides = None
    if output:
        layer_names = {"raw", "processed", "analytics", "rejected"}
        root = output.parent if output.name in layer_names else output
        overrides = {"storage": {"data_root": str(root)}}
    settings = _settings(config, overrides)
    files = iter_files(input_dir, (pattern,))
    if not files:
        _fail(f"no files matching {pattern!r} under {input_dir}", EXIT_USAGE)
    result = process_parallel(files, settings, PipelineOptions(), workers=workers)
    _emit({"files": len(files), **result.summary()}, as_json, title="Batch result")
    raise typer.Exit(EXIT_OK if result.succeeded else EXIT_FAILURE)


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #
@app.command()
def analyze(
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    date: Annotated[str | None, typer.Option(help="Analyse one UTC day (YYYY-MM-DD).")] = None,
    hours: Annotated[float, typer.Option(help="Rolling window ending now.")] = 24.0,
    window: Annotated[str, typer.Option(help="Bucket size: 1m 5m 15m 1h 6h 1d.")] = "5m",
    service: Annotated[str | None, typer.Option(help="Restrict to one service.")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Compute analytics over a window.

    Example: loganalytics analyze --date 2026-08-07
    """
    from app.analytics import AnalyticsEngine
    from app.anomaly_detection import AnomalyService

    settings = _settings(config)
    if date:
        start = parse_timestamp(date)
        if start is None:
            _fail(f"could not parse date {date!r}", EXIT_USAGE)
            return
        start = start.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
    else:
        end = utcnow()
        start = end - timedelta(hours=hours)

    filters = {"service": service} if service else None
    engine = AnalyticsEngine(settings=settings)
    overview = engine.overview(start, end, filters)
    status = engine.status_codes(start, end, filters)
    services = engine.services(start, end, filters, limit=15)
    anomalies = AnomalyService(engine, settings).scan(start, end, window=window)

    payload = {
        "window": f"{to_iso(start)} .. {to_iso(end)}",
        "total_records": overview.total_records,
        "total_requests": overview.total_requests,
        "total_errors": overview.total_errors,
        "error_rate": round(overview.error_rate, 6),
        "avg_latency_ms": overview.average_latency_ms,
        "p95_latency_ms": overview.p95_latency_ms,
        "p99_latency_ms": overview.p99_latency_ms,
        "active_services": overview.active_services,
        "status_classes": status.by_class,
        "anomalies": len(anomalies),
    }
    if as_json:
        payload["services"] = [s.model_dump(mode="json") for s in services.services]
        payload["anomaly_detail"] = [a.model_dump(mode="json") for a in anomalies[:25]]
        _emit(payload, True)
        return

    _emit(payload, False, title="Analytics")
    if services.services:
        table = Table(title="Service health", header_style="bold cyan")
        for column in ("Service", "Requests", "Errors", "Failure", "P95 ms", "Status"):
            table.add_column(column, justify="right" if column != "Service" else "left")
        for item in services.services:
            table.add_row(
                item.service,
                f"{item.requests:,}",
                f"{item.errors:,}",
                f"{item.failure_rate:.2%}",
                f"{item.latency.p95:,.1f}",
                item.status,
            )
        console.print(table)
    if anomalies:
        table = Table(title="Anomalies", header_style="bold yellow")
        for column in ("Time", "Type", "Metric", "Observed", "Expected", "Severity"):
            table.add_column(column)
        for anomaly in anomalies[:20]:
            table.add_row(
                to_iso(anomaly.bucket),
                str(anomaly.type),
                anomaly.metric,
                f"{anomaly.observed:,.1f}",
                f"{anomaly.expected:,.1f}",
                str(anomaly.severity),
            )
        console.print(table)


@app.command()
def search(
    query: Annotated[
        str, typer.Argument(help="Query expression, e.g. 'service=api AND level=ERROR'.")
    ] = "",
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    level: Annotated[str | None, typer.Option(help="Shortcut for level=<LEVEL>.")] = None,
    service: Annotated[str | None, typer.Option()] = None,
    status_code: Annotated[int | None, typer.Option("--status")] = None,
    hours: Annotated[float, typer.Option()] = 24.0,
    limit: Annotated[int, typer.Option("-n", help="Maximum records.")] = 20,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Search log records.

    Example: loganalytics search "service=payment AND status_code>=500"
    """
    from app.search import SearchService

    settings = _settings(config)
    filters = {
        key: value
        for key, value in (
            ("level", level.upper() if level else None),
            ("service", service),
            ("status_code", status_code),
        )
        if value is not None
    }
    end = utcnow()
    try:
        result = SearchService(settings=settings).search(
            query,
            filters=filters,
            start=end - timedelta(hours=hours),
            end=end,
            page_size=limit,
        )
    except LogAnalyticsError as exc:
        _fail(str(exc), EXIT_USAGE)
        return

    if as_json:
        _emit(result.as_dict(), True)
        return
    if not result.items:
        console.print("[dim]no matching records[/dim]")
        raise typer.Exit(EXIT_OK)

    table = Table(
        title=f"{result.total:,} matches ({result.took_ms:.0f} ms)", header_style="bold cyan"
    )
    for column in ("Time", "Level", "Service", "Status", "Endpoint", "Message"):
        table.add_column(column, overflow="ellipsis", no_wrap=column != "Message")
    for item in result.items:
        table.add_row(
            str(item.get("timestamp", ""))[:19],
            str(item.get("level", "")),
            str(item.get("service") or "-"),
            str(item.get("status_code") or "-"),
            str(item.get("endpoint") or "-")[:40],
            str(item.get("message") or "")[:80],
        )
    console.print(table)


@app.command()
def report(
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    daily: Annotated[bool, typer.Option("--daily", help="Report on one calendar day.")] = False,
    date: Annotated[str | None, typer.Option(help="Day for --daily (default: yesterday).")] = None,
    hours: Annotated[float, typer.Option(help="Window for a rolling summary.")] = 24.0,
    fmt: Annotated[OutputFormat, typer.Option("--format", "-f")] = OutputFormat.MARKDOWN,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write to a file.")] = None,
) -> None:
    """Generate a report.

    Example: loganalytics report --daily --format markdown -o report.md
    """
    from app.analytics.reports import ReportBuilder, render_json, render_markdown, save_report

    settings = _settings(config)
    builder = ReportBuilder(settings)
    report_obj = builder.daily(parse_timestamp(date)) if daily else builder.summary(hours)

    if output:
        path = save_report(
            report_obj,
            output.parent if output.suffix else output,
            fmt="json" if fmt is OutputFormat.JSON else "markdown",
            filename=output.name if output.suffix else None,
        )
        console.print(f"[green]written[/green] {path}")
        return
    if fmt is OutputFormat.JSON:
        _write_json(render_json(report_obj))
    else:
        console.print(render_markdown(report_obj))


@app.command()
def stats(
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show dataset and platform statistics."""
    from app.storage import MetadataStore, build_engine
    from app.validation.dlq import rejection_stats

    settings = _settings(config)
    engine = build_engine(settings)
    summary = engine.dataset_summary()
    rejected = rejection_stats(settings.rejected_path)

    payload: dict[str, Any] = {
        "data_root": str(settings.storage.data_root),
        "format": settings.storage.format,
        "records": summary.get("records", 0),
        "services": summary.get("services", 0),
        "first_event": to_iso(summary["first_event"]) if summary.get("first_event") else None,
        "last_event": to_iso(summary["last_event"]) if summary.get("last_event") else None,
        "rejected_total": sum(rejected.values()),
        "rejected_by_reason": rejected,
    }
    try:
        store = MetadataStore.from_settings(settings)
        store.create_schema()
        payload.update(store.run_stats())
        store.close()
    except LogAnalyticsError:
        payload["runs"] = "metadata store unavailable"

    _emit(payload, as_json, title="Platform statistics")


# --------------------------------------------------------------------------- #
# Data generation and serving
# --------------------------------------------------------------------------- #
@app.command()
def generate(
    output: Annotated[Path, typer.Argument(help="Output file (.log, .jsonl, .csv, .gz).")],
    count: Annotated[int, typer.Option("-n", help="Number of records.")] = 100_000,
    fmt: Annotated[
        str, typer.Option("--format", "-f", help="json|access|plaintext|csv|mixed.")
    ] = "json",
    hours: Annotated[float, typer.Option(help="Time span the data covers.")] = 24.0,
    seed: Annotated[int, typer.Option(help="PRNG seed - same seed, same dataset.")] = 1337,
) -> None:
    """Generate a realistic synthetic dataset.

    Example: loganalytics generate data/raw/demo.log -n 1000000 --format mixed
    """
    from app.synthetic import generate_dataset

    with console.status(f"generating {count:,} records..."):
        path = generate_dataset(output, count=count, fmt=fmt, seed=seed, duration_hours=hours)
    size_mb = path.stat().st_size / 1024**2
    console.print(f"[green]generated[/green] {count:,} records -> {path} ({size_mb:,.1f} MiB)")


@app.command()
def serve(
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    host: Annotated[str | None, typer.Option(help="Bind address.")] = None,
    port: Annotated[int | None, typer.Option(help="Bind port.")] = None,
    reload: Annotated[
        bool, typer.Option("--reload", help="Auto-reload (development only).")
    ] = False,
) -> None:
    """Run the API server."""
    import uvicorn

    settings = _settings(config)
    bind_host = host or settings.api.host
    console.print(
        f"[green]serving[/green] http://{bind_host}:{port or settings.api.port} "
        f"(dashboard: /dashboard, docs: {'/docs' if settings.api.docs_enabled else 'disabled'})"
    )
    uvicorn.run(
        "app.api.main:create_app",
        factory=True,
        host=bind_host,
        port=port or settings.api.port,
        reload=reload,
        log_config=None,
        access_log=False,
    )


@app.command()
def stream(
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    source: Annotated[str, typer.Option(help="'kafka' or a file to tail line by line.")] = "kafka",
    fmt: Annotated[str, typer.Option("--format", "-f", help="Parser for each message.")] = "json",
    max_batches: Annotated[int | None, typer.Option(help="Stop after N batches.")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Consume a live stream into the processed layer.

    Records become queryable within `streaming.flush_interval_seconds`, and
    offsets are only acknowledged after a successful flush.

    Example: loganalytics stream --source kafka
    """
    from app.streaming import StreamProcessor

    settings = _settings(config)
    if not settings.streaming.enabled:
        _fail("streaming is disabled; set streaming.enabled to true", EXIT_USAGE)

    if source == "kafka":
        from app.streaming.kafka_consumer import consume

        console.print(
            f"[green]consuming[/green] topic '{settings.streaming.topic}' "
            f"from {', '.join(settings.streaming.brokers)}"
        )
        snapshot = consume(settings, parser=fmt, max_batches=max_batches)
        _emit(snapshot["stats"], as_json, title="Stream")
        return

    path = Path(source)
    if not path.is_file():
        _fail(f"not a file: {source}", EXIT_USAGE)
    processor = StreamProcessor(settings, parser=fmt)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        stats = processor.run(line.rstrip() for line in handle if line.strip())
    _emit(stats.as_dict(), as_json, title="Stream")


@app.command()
def plugins(
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List registered parsers, sources, backends and detectors."""
    import app.parsers  # noqa: F401 - registers parsers
    import app.workers  # noqa: F401 - registers jobs
    from app.anomaly_detection.detectors import anomaly_registry
    from app.core.registry import Registry
    from app.deduplication.strategies import dedup_registry
    from app.ingestion.base import source_registry
    from app.parsers.base import parser_registry
    from app.storage.base import storage_registry
    from app.workers.queue import available_jobs

    registries: dict[str, Registry[Any]] = {
        "parsers": parser_registry,
        "sources": source_registry,
        "storage": storage_registry,
        "deduplication": dedup_registry,
        "anomaly_detectors": anomaly_registry,
    }
    if as_json:
        _emit(
            {name: registry.describe() for name, registry in registries.items()}
            | {"jobs": available_jobs()},
            True,
        )
        return
    for name, registry in registries.items():
        table = Table(title=name, header_style="bold cyan")
        table.add_column("name")
        table.add_column("implementation", style="dim")
        for entry in registry.describe():
            table.add_row(entry["name"], entry["implementation"])
        console.print(table)
    console.print(f"[cyan]jobs:[/cyan] {', '.join(available_jobs())}")


# --------------------------------------------------------------------------- #
# Sub-commands
# --------------------------------------------------------------------------- #
config_app = typer.Typer(help="Inspect and validate configuration.")
app.add_typer(config_app, name="config")


@config_app.command("show")
def config_show(
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
) -> None:
    """Print the effective configuration (secrets redacted)."""
    _write_json(json_module.dumps(_settings(config).safe_dump(), default=str, indent=2))


@config_app.command("validate")
def config_validate(
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    environment: Annotated[str | None, typer.Option(help="Validate as this environment.")] = None,
) -> None:
    """Validate configuration, optionally against production rules."""
    overrides = {"environment": environment} if environment else None
    try:
        settings = load_settings(config, overrides)
    except LogAnalyticsError as exc:
        _fail(str(exc), EXIT_USAGE)
        return
    console.print(f"[green]valid[/green] (environment: {settings.environment})")


apikey_app = typer.Typer(help="Manage API keys.")
app.add_typer(apikey_app, name="apikey")


@apikey_app.command("create")
def apikey_create(
    name: Annotated[str, typer.Argument(help="A label for the key.")],
    scopes: Annotated[str, typer.Option(help="Comma-separated: read,write,admin.")] = "read",
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
) -> None:
    """Mint an API key.  The plaintext is shown once and never stored."""
    from app.storage import MetadataStore

    settings = _settings(config)
    requested = [s.strip() for s in scopes.split(",") if s.strip()]
    invalid = sorted(set(requested) - {"read", "write", "admin"})
    if invalid:
        _fail(f"unknown scopes: {', '.join(invalid)}", EXIT_USAGE)
    store = MetadataStore.from_settings(settings)
    store.create_schema()
    secret = store.create_api_key(name, requested)
    store.close()
    console.print(f"[green]created[/green] key '{name}' with scopes {requested}")
    console.print(f"[bold yellow]{secret}[/bold yellow]")
    console.print("[dim]Store this now - it cannot be shown again.[/dim]")


@apikey_app.command("list")
def apikey_list(
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
) -> None:
    """List API keys (never their values)."""
    from app.storage import MetadataStore

    store = MetadataStore.from_settings(_settings(config))
    store.create_schema()
    keys = store.list_api_keys()
    store.close()
    _emit(keys or [{"name": "-", "scopes": "-", "active": "-"}], False, title="API keys")


@apikey_app.command("revoke")
def apikey_revoke(
    name: Annotated[str, typer.Argument()],
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
) -> None:
    """Revoke an API key."""
    from app.storage import MetadataStore

    store = MetadataStore.from_settings(_settings(config))
    store.create_schema()
    revoked = store.revoke_api_key(name)
    store.close()
    if not revoked:
        _fail(f"no such key: {name}")
    console.print(f"[green]revoked[/green] {name}")


dlq_app = typer.Typer(help="Inspect the dead-letter queue.")
app.add_typer(dlq_app, name="dlq")


@dlq_app.command("stats")
def dlq_stats(
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Rejection counts by reason."""
    from app.validation.dlq import rejection_stats

    settings = _settings(config)
    counts = rejection_stats(settings.rejected_path)
    _emit({"total": sum(counts.values()), **counts}, as_json, title="Rejected records")


@dlq_app.command("show")
def dlq_show(
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    limit: Annotated[int, typer.Option("-n")] = 10,
) -> None:
    """Show recent rejected records with their reasons."""
    from app.validation.dlq import iter_rejected

    settings = _settings(config)
    table = Table(title="Dead-letter queue", header_style="bold red")
    for column in ("Reason", "Stage", "Line", "Detail", "Raw"):
        table.add_column(column, overflow="ellipsis", no_wrap=True)
    shown = 0
    for record in iter_rejected(settings.rejected_path):
        table.add_row(
            str(record.get("reason")),
            str(record.get("stage")),
            str(record.get("line_number") or "-"),
            str(record.get("detail") or "")[:50],
            str(record.get("raw") or "")[:60],
        )
        shown += 1
        if shown >= limit:
            break
    console.print(table if shown else "[dim]no rejected records[/dim]")


jobs_app = typer.Typer(help="Run background jobs.")
app.add_typer(jobs_app, name="job")


@jobs_app.command("run")
def job_run(
    name: Annotated[str, typer.Argument(help="Job name (see 'loganalytics plugins').")],
    params: Annotated[str, typer.Option("--params", help="JSON object of arguments.")] = "{}",
    config: Annotated[Path | None, typer.Option("--config", "-c")] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run a registered job synchronously."""
    import app.workers  # noqa: F401 - registers jobs
    from app.workers.queue import _HANDLERS, available_jobs

    _settings(config)
    handler = _HANDLERS.get(name)
    if handler is None:
        _fail(f"unknown job {name!r}; available: {', '.join(available_jobs())}", EXIT_USAGE)
        return
    try:
        arguments = json_module.loads(params)
    except ValueError as exc:
        _fail(f"--params must be a JSON object: {exc}", EXIT_USAGE)
        return
    result = handler(**arguments)
    _emit(result, as_json, title=f"job: {name}")


def run() -> None:  # pragma: no cover - console-script entry point
    """Entry point registered as the ``loganalytics`` command."""
    try:
        app()
    except LogAnalyticsError as exc:
        error_console.print(f"[bold red]error:[/bold red] {exc}")
        sys.exit(EXIT_FAILURE)
    except KeyboardInterrupt:
        error_console.print("[yellow]interrupted[/yellow]")
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    run()
