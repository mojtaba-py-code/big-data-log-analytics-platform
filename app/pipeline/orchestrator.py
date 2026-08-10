"""The batch processing pipeline.

    Source → Parse → Clean → Normalise → Enrich → Validate → Deduplicate → Store

Design
------
The whole pipeline is a **chain of generators**.  Nothing between the source
and the storage writer ever holds more than one record, so peak memory is
governed by the storage batch size alone — not by input size.  That single
property is what lets the same code run a 5 KB sample in a unit test and a
40 GB archive in production.

Failure policy
--------------
* A bad *record* never fails a *run*: it is dead-lettered with a reason and the
  stream continues.
* If the rejection rate crosses ``processing.error_threshold``, the run aborts
  — that pattern means the format guess or the source itself is wrong, and
  continuing would write millions of garbage rows.
* SIGINT/SIGTERM triggers a **graceful stop**: the current record finishes, the
  writers flush and rename their temp files, and the partial result is
  reported.  A killed run therefore leaves a consistent dataset, not a
  half-written Parquet file.

Idempotency
-----------
``event_id`` is derived from record content, and output files are named after
the run.  Re-running a failed job over the same input produces the same ids and
overwrites the same files rather than appending duplicates.
"""

from __future__ import annotations

import signal
import threading
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import Settings, get_settings
from app.core.exceptions import (
    LogAnalyticsError,
    ParseError,
    PipelineError,
    StorageError,
)
from app.core.logging import get_logger, log_context, set_request_id
from app.core.masking import Masker
from app.core.metrics import MetricsRegistry, memory_usage_mb
from app.core.paths import ensure_directory
from app.core.timeutil import utcnow
from app.deduplication import Deduplicator
from app.ingestion import LogSource, RawRecord, build_source
from app.models.enums import RejectReason, SourceType
from app.models.log_event import LogEvent
from app.models.results import PipelineResult, StageStats
from app.parsers import LogParser, ParseContext, detect_format, get_parser
from app.parsers.structured import StructuredParser
from app.storage import StorageBackend, build_store
from app.transformation import TransformationChain
from app.validation import DeadLetterQueue, RecordValidator

log = get_logger(__name__)


@dataclass(slots=True)
class PipelineOptions:
    """Per-run overrides that do not belong in global configuration."""

    parser: str | None = None
    service: str | None = None
    environment: str | None = None
    keep_raw: bool = True
    dry_run: bool = False
    limit: int | None = None
    layer: str = "processed"
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])


class GracefulShutdown:
    """Flips a flag on SIGINT/SIGTERM so loops can stop at a safe point.

    Signal handlers are only installed on the main thread; inside a worker
    thread (the API, Celery) the object is inert, which is correct — the host
    owns signal handling there.
    """

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._previous: dict[int, Any] = {}

    def __enter__(self) -> GracefulShutdown:
        if threading.current_thread() is threading.main_thread():
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    self._previous[sig] = signal.signal(sig, self._handle)
                except (ValueError, OSError):  # pragma: no cover - platform dependent
                    continue
        return self

    def __exit__(self, *exc: object) -> None:
        for sig, handler in self._previous.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):  # pragma: no cover
                continue
        self._previous.clear()

    def _handle(self, signum: int, _frame: Any) -> None:
        log.warning("shutdown signal received; finishing current batch", extra={"signal": signum})
        self._stop.set()

    @property
    def requested(self) -> bool:
        return self._stop.is_set()


class LogPipeline:
    """Wires the stages together and runs them over a source."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        store: StorageBackend | None = None,
        dlq: DeadLetterQueue | None = None,
        metrics: MetricsRegistry | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.metrics = metrics or MetricsRegistry()
        self._store_override = store
        self._dlq_override = dlq

    # -- public API ---------------------------------------------------------- #
    def run(
        self,
        target: str | Path | LogSource,
        options: PipelineOptions | None = None,
    ) -> PipelineResult:
        """Process one source end to end."""
        opts = options or PipelineOptions()
        set_request_id(opts.run_id)
        result = PipelineResult(run_id=opts.run_id, sources=[str(target)])
        try:
            source = (
                target if isinstance(target, LogSource) else build_source(target, self.settings)
            )
        except (LogAnalyticsError, OSError) as exc:
            # An unreadable target is a *result*, not an exception: a batch run
            # over many files must record it and carry on with the rest.
            result.succeeded = False
            result.errors.append(f"{type(exc).__name__}: {exc}")
            result.finished_at = utcnow()
            log.error(
                "source could not be opened",
                extra={"source": str(target), "error_type": type(exc).__name__},
            )
            return result
        result.sources = [source.describe()]

        store = self._store_override or self._build_store(opts)
        dlq = self._dlq_override or DeadLetterQueue(
            self.settings.rejected_path,
            run_id=opts.run_id,
            masker=self._masker(),
            enabled=not opts.dry_run,
        )

        with log_context(run_id=opts.run_id, source=source.describe()), GracefulShutdown() as stop:
            try:
                self._execute(source, store, dlq, result, opts, stop)
            except PipelineError as exc:
                result.succeeded = False
                result.errors.append(str(exc))
                log.error("pipeline aborted", extra={"error_type": type(exc).__name__})
            except Exception as exc:  # noqa: BLE001 - surface, never swallow
                result.succeeded = False
                result.errors.append(f"{type(exc).__name__}: {exc}")
                log.exception("pipeline failed unexpectedly")
            finally:
                self._finalise(store, dlq, source, result, opts)

        log.info("pipeline finished", extra=result.summary())
        return result

    def run_many(
        self, targets: Iterable[str | Path], options: PipelineOptions | None = None
    ) -> PipelineResult:
        """Process several sources sequentially into one aggregated result."""
        opts = options or PipelineOptions()
        combined = PipelineResult(run_id=opts.run_id)
        for target in targets:
            partial = self.run(target, PipelineOptions(**{**opts.__dict__, "run_id": opts.run_id}))
            combined.merge(partial)
        combined.finished_at = utcnow()
        return combined

    # -- internals ----------------------------------------------------------- #
    def _masker(self) -> Masker:
        return Masker(
            rules=self.settings.masking.rules,
            extra_field_names=self.settings.masking.extra_fields,
            enabled=self.settings.masking.enabled,
        )

    def _build_store(self, opts: PipelineOptions) -> StorageBackend:
        root = {
            "raw": self.settings.raw_path,
            "processed": self.settings.processed_path,
            "analytics": self.settings.analytics_path,
        }.get(opts.layer, self.settings.processed_path)
        ensure_directory(root)
        return build_store(root, self.settings)

    def _execute(
        self,
        source: LogSource,
        store: StorageBackend,
        dlq: DeadLetterQueue,
        result: PipelineResult,
        opts: PipelineOptions,
        stop: GracefulShutdown,
    ) -> None:
        parser, context = self._prepare_parser(source, opts)
        log.info(
            "processing source",
            extra={"parser": parser.name, "source": source.describe()},
        )

        transformer = TransformationChain.from_settings(
            self.settings, default_service=context.default_service
        )
        validator = RecordValidator(self.settings.validation)
        deduplicator = Deduplicator.from_settings(self.settings.deduplication)

        events = self._stage_parse(source, parser, context, dlq, result, opts, stop)
        events = self._stage_transform(events, transformer, dlq, result)
        events = self._stage_validate(events, validator, dlq, result)
        events = self._stage_dedup(events, deduplicator, dlq, result)

        if opts.dry_run:
            for _ in events:
                pass
        else:
            with self.metrics.timer("store"):
                written = store.write(events, run_id=opts.run_id)
            result.outputs = [str(path) for path in written]
            result.records_written = store.records_written

        result.records_duplicate = deduplicator.stats.duplicates
        result.stages.append(
            StageStats(
                name="deduplication",
                processed=deduplicator.stats.seen,
                passed=deduplicator.stats.unique,
                rejected=deduplicator.stats.duplicates,
            )
        )
        self.metrics.set_gauge("peak_memory_mb", memory_usage_mb())
        result.peak_memory_mb = memory_usage_mb()

    def _prepare_parser(
        self, source: LogSource, opts: PipelineOptions
    ) -> tuple[LogParser, ParseContext]:
        service = opts.service or source.suggested_service()
        context = ParseContext(
            source=source.describe(),
            source_type=source.source_type,
            default_service=service,
            keep_raw=opts.keep_raw,
        )
        if opts.environment:
            from app.models.enums import Environment

            try:
                context.environment = Environment(opts.environment.lower())
            except ValueError:
                log.warning("unknown environment override", extra={"value": opts.environment})

        if opts.parser:
            return get_parser(opts.parser), context

        sample = source.sample(self.settings.processing.format_sample_lines)
        if not sample:
            # Structured sources (DB rows, JSON APIs) have no text sample; the
            # structured parser handles their mappings directly.
            return get_parser("json"), context
        detection = detect_format(sample, filename=source.describe(), context=context)
        log.info(
            "detected log format",
            extra={
                "parser": detection.parser_name,
                "score": detection.score,
                "success_rate": round(detection.success_rate, 3),
                "candidates": [name for name, _ in detection.candidates],
            },
        )
        if detection.success_rate < 0.5:
            log.warning(
                "low parser confidence; consider passing --format",
                extra={"parser": detection.parser_name},
            )
        return get_parser(detection.parser_name), context

    # -- stages -------------------------------------------------------------- #
    def _stage_parse(
        self,
        source: LogSource,
        parser: LogParser,
        context: ParseContext,
        dlq: DeadLetterQueue,
        result: PipelineResult,
        opts: PipelineOptions,
        stop: GracefulShutdown,
    ) -> Iterator[LogEvent]:
        threshold = self.settings.processing.error_threshold
        checked_at = 0
        for record in source.read():
            if stop.requested:
                log.warning(
                    "stopping early on shutdown request", extra={"lines": result.lines_read}
                )
                break
            result.lines_read += 1
            if opts.limit is not None and result.records_parsed >= opts.limit:
                break

            event = self._parse_one(record, parser, context, dlq, result)
            if event is not None:
                result.records_parsed += 1
                yield event

            # Abort a hopeless run, but only after a meaningful sample.
            if result.lines_read - checked_at >= 10_000:
                checked_at = result.lines_read
                if result.lines_read >= 1_000 and result.rejection_rate > threshold:
                    raise PipelineError(
                        "rejection rate exceeded the configured threshold; "
                        "the source format is probably wrong",
                        rejection_rate=round(result.rejection_rate, 4),
                        threshold=threshold,
                    )
        result.bytes_read = source.stats.bytes_read

    def _parse_one(
        self,
        record: RawRecord,
        parser: LogParser,
        context: ParseContext,
        dlq: DeadLetterQueue,
        result: PipelineResult,
    ) -> LogEvent | None:
        context.line_number = record.line_number
        if record.context:
            context.extra.update(record.context)
        try:
            if record.is_structured:
                if isinstance(parser, StructuredParser):
                    return parser.parse_record(record.payload, context)  # type: ignore[arg-type]
                from app.parsers.structured import JsonLineParser

                return JsonLineParser().parse_record(record.payload, context)  # type: ignore[arg-type]
            return parser.parse(record.payload, context)  # type: ignore[arg-type]
        except ParseError as exc:
            dlq.record(
                record.text,
                RejectReason.UNPARSEABLE,
                stage="parse",
                detail=str(exc),
                source=record.source,
                line_number=record.line_number,
            )
            result.record_rejection(RejectReason.UNPARSEABLE)
            self.metrics.increment_label("rejections", str(RejectReason.UNPARSEABLE))
            return None
        except (ValueError, TypeError) as exc:
            # A schema violation: the parser produced a field the model refused.
            dlq.record(
                record.text,
                RejectReason.SCHEMA_VIOLATION,
                stage="parse",
                detail=f"{type(exc).__name__}: {exc}",
                source=record.source,
                line_number=record.line_number,
            )
            result.record_rejection(RejectReason.SCHEMA_VIOLATION)
            self.metrics.increment_label("rejections", str(RejectReason.SCHEMA_VIOLATION))
            return None

    def _stage_transform(
        self,
        events: Iterable[LogEvent],
        chain: TransformationChain,
        dlq: DeadLetterQueue,
        result: PipelineResult,  # noqa: ARG002 - mutated via record_rejection
    ) -> Iterator[LogEvent]:
        for event in events:
            try:
                yield chain.apply(event)
            except Exception as exc:  # noqa: BLE001 - one record must not kill the run
                dlq.record_event(
                    event, RejectReason.TRANSFORM_ERROR, stage="transform", detail=str(exc)
                )
                result.record_rejection(RejectReason.TRANSFORM_ERROR)
                self.metrics.increment_label("rejections", str(RejectReason.TRANSFORM_ERROR))

    def _stage_validate(
        self,
        events: Iterable[LogEvent],
        validator: RecordValidator,
        dlq: DeadLetterQueue,
        result: PipelineResult,
    ) -> Iterator[LogEvent]:
        for event in events:
            outcome = validator.validate(event)
            for warning in outcome.warnings:
                self.metrics.increment_label("validation_warnings", warning.rule)
            if outcome.valid:
                result.records_valid += 1
                yield event
                continue
            issue = outcome.fatal_issue
            reason = issue.reason if issue else RejectReason.SCHEMA_VIOLATION
            dlq.record_event(event, reason, stage="validate", detail=issue.detail if issue else "")
            result.record_rejection(reason)
            self.metrics.increment_label("rejections", str(reason))

    def _stage_dedup(
        self,
        events: Iterable[LogEvent],
        deduplicator: Deduplicator,
        dlq: DeadLetterQueue,
        result: PipelineResult,  # noqa: ARG002 - mutated via record_rejection
    ) -> Iterator[LogEvent]:
        keep_duplicates = self.settings.deduplication.keep_duplicates
        for event, duplicate in deduplicator.partition(events):
            if not duplicate:
                yield event
                continue
            self.metrics.increment("duplicates")
            if keep_duplicates:
                dlq.record_event(event, RejectReason.DUPLICATE, stage="deduplicate")

    # -- teardown ------------------------------------------------------------ #
    def _finalise(
        self,
        store: StorageBackend,
        dlq: DeadLetterQueue,
        source: LogSource,
        result: PipelineResult,
        opts: PipelineOptions,
    ) -> None:
        try:
            if not opts.dry_run:
                store.flush()
                result.records_written = store.records_written
                result.outputs = [str(p) for p in store.files_written]
        except StorageError as exc:
            result.succeeded = False
            result.errors.append(str(exc))
            log.error("failed to flush storage", extra={"error_type": type(exc).__name__})
        finally:
            dlq.close()
            source.close()
            result.finished_at = utcnow()
            result.bytes_read = max(result.bytes_read, source.stats.bytes_read)
            if dlq.total and not result.rejection_reasons:
                result.rejection_reasons = dlq.counts()
            self.metrics.increment("records_written", result.records_written)
            self.metrics.increment("lines_read", result.lines_read)


def process_source(
    target: str | Path,
    settings: Settings | None = None,
    options: PipelineOptions | None = None,
) -> PipelineResult:
    """Convenience entry point used by the CLI and background workers."""
    return LogPipeline(settings).run(target, options)


__all__ = [
    "GracefulShutdown",
    "LogPipeline",
    "PipelineOptions",
    "SourceType",
    "process_source",
]
