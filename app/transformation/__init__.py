"""Transformation layer: clean → normalise → enrich.

The three stages are separate classes rather than one ``transform()`` because
they have different failure modes and different test shapes: cleaning is a
string-level repair, normalisation is a domain mapping, enrichment is a
security control.  :class:`TransformationChain` composes them in the one order
that is correct (see :mod:`app.transformation.enrichment` for why).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, runtime_checkable

from app.core.config import Settings
from app.core.masking import Masker
from app.models.log_event import LogEvent
from app.transformation.cleaning import RecordCleaner, clean_text, fix_mojibake
from app.transformation.enrichment import RecordEnricher
from app.transformation.normalization import (
    RecordNormalizer,
    classify_ip,
    infer_environment,
    normalise_hostname,
    normalise_service,
    template_endpoint,
    user_agent_family,
)


@runtime_checkable
class Transformer(Protocol):
    """Anything that maps one event to another."""

    def __call__(self, event: LogEvent) -> LogEvent: ...


class TransformationChain:
    """Runs the transformation stages in order."""

    def __init__(self, stages: Sequence[Transformer]) -> None:
        self._stages = tuple(stages)

    @classmethod
    def from_settings(
        cls, settings: Settings, *, default_service: str | None = None
    ) -> TransformationChain:
        masker = Masker(
            rules=settings.masking.rules,
            extra_field_names=settings.masking.extra_fields,
            enabled=settings.masking.enabled,
        )
        cleaner = RecordCleaner(max_message_length=settings.validation.max_message_length)
        normalizer = RecordNormalizer(default_service=default_service)
        enricher = RecordEnricher(masker, mask_raw_message=settings.masking.mask_raw_message)
        return cls([cleaner.clean, normalizer.normalise, enricher.enrich])

    def apply(self, event: LogEvent) -> LogEvent:
        for stage in self._stages:
            event = stage(event)
        return event

    def apply_many(self, events: Iterable[LogEvent]) -> Iterable[LogEvent]:
        for event in events:
            yield self.apply(event)

    def __len__(self) -> int:
        return len(self._stages)


__all__ = [
    "RecordCleaner",
    "RecordEnricher",
    "RecordNormalizer",
    "TransformationChain",
    "Transformer",
    "classify_ip",
    "clean_text",
    "fix_mojibake",
    "infer_environment",
    "normalise_hostname",
    "normalise_service",
    "template_endpoint",
    "user_agent_family",
]
