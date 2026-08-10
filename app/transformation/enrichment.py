"""Enrichment: masking and derived attributes.

Responsibility
--------------
The **last** transformation stage before a record is persisted.  Two jobs:

1. **Redaction.**  Apply :class:`~app.core.masking.Masker` to the message, the
   raw line and metadata.  Doing this here — rather than at query time — means
   a secret is never written to disk in the first place, which is the only
   redaction that survives a stolen backup.
2. **Derived attributes** that are expensive or awkward to compute in SQL:
   the status class, an error flag and whether the record itself looked like it
   contained a credential (a signal the security analytics layer consumes).

Ordering matters
----------------
Enrichment runs after cleaning and normalisation.  If masking ran first, a
secret split across a mojibake boundary or an escaped newline could evade the
patterns and then be repaired into plaintext by the cleaner.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.core.masking import Masker, default_masker
from app.models.log_event import LogEvent


class RecordEnricher:
    """Masks sensitive content and attaches derived fields."""

    def __init__(
        self,
        masker: Masker | None = None,
        *,
        mask_raw_message: bool = True,
        flag_secrets: bool = True,
        drop_raw_message: bool = False,
    ) -> None:
        self.masker = masker or default_masker
        self.mask_raw_message = mask_raw_message
        self.flag_secrets = flag_secrets
        #: Dropping the raw line saves ~60 % of stored bytes.  Off by default:
        #: incident response usually needs the original text.
        self.drop_raw_message = drop_raw_message

    def enrich(self, event: LogEvent) -> LogEvent:
        updates: dict[str, object] = {}
        metadata = dict(event.metadata)

        contained_secret = False
        if self.masker.enabled:
            if event.message:
                masked = self.masker.mask_text(event.message)
                if masked != event.message:
                    contained_secret = True
                    updates["message"] = masked
            for field_name in ("user_agent", "referrer", "endpoint", "user_id"):
                value = getattr(event, field_name)
                if isinstance(value, str) and value:
                    masked_value = self.masker.mask_text(value)
                    if masked_value != value:
                        contained_secret = True
                        updates[field_name] = masked_value
            if metadata:
                masked_meta = self.masker.mask_mapping(metadata)
                if masked_meta != metadata:
                    contained_secret = True
                    metadata = masked_meta
            if event.raw_message:
                if self.drop_raw_message:
                    updates["raw_message"] = ""
                elif self.mask_raw_message:
                    masked_raw = self.masker.mask_text(event.raw_message)
                    if masked_raw != event.raw_message:
                        contained_secret = True
                        updates["raw_message"] = masked_raw
        elif self.drop_raw_message and event.raw_message:
            updates["raw_message"] = ""

        if event.status_code is not None:
            metadata["status_class"] = f"{event.status_code // 100}xx"
        if event.is_error:
            metadata["is_error"] = True
        if self.flag_secrets and contained_secret:
            # Not an alert in itself, but a strong signal: an application that
            # logs credentials is a finding the security layer should surface.
            metadata["masked"] = True

        if metadata != event.metadata:
            updates["metadata"] = metadata
        if not updates:
            return event
        return event.model_copy(update=updates)

    def enrich_many(self, events: Iterable[LogEvent]) -> Iterable[LogEvent]:
        for event in events:
            yield self.enrich(event)


__all__ = ["RecordEnricher"]
