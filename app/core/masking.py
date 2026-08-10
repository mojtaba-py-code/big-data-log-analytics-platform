"""Sensitive-data detection and masking.

Responsibility
--------------
Logs are the single most common place where secrets leak.  This module is the
one authority on *what* counts as sensitive and *how* it is redacted, so the
rule set can be audited in a single file.

It is applied in three places:

1. :mod:`app.transformation.enrichment` — before a record is persisted.
2. :mod:`app.core.logging` — on every application log record we emit ourselves.
3. :mod:`app.api.errors` — before an error body leaves the process.

Design notes
------------
* Masking is **irreversible** by design: we keep a short prefix at most, never
  enough to reconstruct the secret.
* Patterns are pre-compiled once at import time; ``mask_text`` is on the hot
  path of every ingested record, so it must stay allocation-light.
* Every pattern is anchored on a *bounded* quantifier.  Unbounded ``.*`` inside
  alternation is what turns a redaction regex into a ReDoS vector.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

REDACTED: Final[str] = "***REDACTED***"

#: Field names whose *value* is always masked, regardless of content.
SENSITIVE_FIELD_NAMES: Final[frozenset[str]] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "api-key",
        "authorization",
        "auth",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "session",
        "session_id",
        "sessionid",
        "private_key",
        "client_secret",
        "credit_card",
        "card_number",
        "cvv",
        "ssn",
        "otp",
        "x-api-key",
    }
)

_KV_KEYS = "|".join(re.escape(k) for k in sorted(SENSITIVE_FIELD_NAMES, key=len, reverse=True))

#: (name, compiled pattern, replacement) triples.  Order matters: the most
#: specific patterns run first so a generic one cannot swallow them.
_PATTERNS: Final[tuple[tuple[str, re.Pattern[str], str], ...]] = (
    (
        # Authorization: Bearer <token>  /  Basic <b64>
        "authorization_header",
        re.compile(
            r"(?i)\b(authorization\s*[:=]\s*)(bearer|basic|token)?\s*[A-Za-z0-9._\-+/=]{8,512}"
        ),
        r"\1" + REDACTED,
    ),
    (
        # key=value / "key": "value" for any sensitive field name
        "sensitive_kv",
        re.compile(rf"(?i)\b({_KV_KEYS})(\"?\s*[:=]\s*\"?)([^\"'\s,;&}}\]]{{1,512}})"),
        r"\1\2" + REDACTED,
    ),
    (
        # JWT: three base64url segments
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{4,2048}\.[A-Za-z0-9_-]{4,4096}\.[A-Za-z0-9_-]{0,2048}\b"),
        REDACTED,
    ),
    (
        # Common vendor key shapes (AWS, GitHub, Slack, Stripe, Google)
        "vendor_key",
        re.compile(
            r"\b(?:AKIA[0-9A-Z]{16}"
            r"|gh[pousr]_[A-Za-z0-9]{20,255}"
            r"|xox[baprs]-[A-Za-z0-9-]{10,255}"
            r"|sk_(?:live|test)_[A-Za-z0-9]{16,255}"
            r"|AIza[0-9A-Za-z_-]{35})\b"
        ),
        REDACTED,
    ),
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----"
            r"[\s\S]{0,8192}?"
            r"-----END [A-Z ]{0,40}PRIVATE KEY-----"
        ),
        REDACTED,
    ),
    (
        "credit_card",
        re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        REDACTED,
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b"),
        REDACTED,
    ),
    (
        # E.164-ish and common national formats, deliberately conservative.
        "phone",
        re.compile(
            r"(?<![\w.])\+?\d{1,3}[ .\-]?\(?\d{2,4}\)?[ .\-]?\d{3,4}[ .\-]?\d{3,4}(?![\w.])"
        ),
        REDACTED,
    ),
)

_PATTERN_INDEX: Final[dict[str, tuple[re.Pattern[str], str]]] = {
    name: (pattern, replacement) for name, pattern, replacement in _PATTERNS
}

#: Patterns enabled by default.  ``credit_card``/``phone`` are the most
#: aggressive (they can swallow long numeric IDs) and stay opt-in per-config.
DEFAULT_RULES: Final[tuple[str, ...]] = (
    "authorization_header",
    "sensitive_kv",
    "jwt",
    "vendor_key",
    "private_key_block",
    "email",
)

ALL_RULES: Final[tuple[str, ...]] = tuple(name for name, _, _ in _PATTERNS)

#: Beyond this length we skip regex masking entirely.  A pathological 10 MB
#: "line" is a denial-of-service vector, not a log record.
MAX_MASKABLE_LENGTH: Final[int] = 64 * 1024

#: Cheap substring triggers per rule.  Masking runs on every field of every
#: record, and the overwhelming majority of log lines contain no secret at all.
#: A substring scan (C-speed ``str.__contains__``) is roughly 30x cheaper than
#: a regex pass, so a line that trips no trigger skips the regexes entirely.
#: Each trigger set must be a *superset* of what its pattern can match —
#: getting this wrong means a secret slips through, so the sets are
#: deliberately generous and covered by dedicated tests.
_TRIGGERS: Final[dict[str, tuple[str, ...]]] = {
    "authorization_header": ("authorization",),
    "sensitive_kv": tuple(sorted(SENSITIVE_FIELD_NAMES)),
    "jwt": ("eyj",),
    "vendor_key": (
        "akia",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "xox",
        "sk_live_",
        "sk_test_",
        "aiza",
    ),
    "private_key_block": ("-----begin",),
    "credit_card": tuple(str(d) for d in range(10)),
    "email": ("@",),
    "phone": tuple(str(d) for d in range(10)),
}


class Masker:
    """Applies a configured subset of redaction rules to text and mappings.

    Parameters
    ----------
    rules:
        Names of the patterns to enable.  Unknown names raise ``KeyError`` at
        construction time — fail loudly at boot rather than silently shipping
        an unredacted pipeline.
    extra_field_names:
        Additional mapping keys whose values are always redacted.
    enabled:
        Global kill switch.  Kept explicit so tests can prove the *unmasked*
        path is only reachable when deliberately disabled.
    """

    __slots__ = ("_compiled", "_field_names", "_triggers", "enabled", "rules")

    def __init__(
        self,
        rules: Sequence[str] = DEFAULT_RULES,
        extra_field_names: Sequence[str] = (),
        *,
        enabled: bool = True,
    ) -> None:
        unknown = [r for r in rules if r not in _PATTERN_INDEX]
        if unknown:
            raise KeyError(f"unknown masking rules: {sorted(unknown)}")
        self.rules: tuple[str, ...] = tuple(rules)
        self.enabled = enabled
        self._compiled: tuple[tuple[re.Pattern[str], str], ...] = tuple(
            _PATTERN_INDEX[name] for name in rules
        )
        triggers = sorted({trigger for name in rules for trigger in _TRIGGERS[name]})
        # One compiled alternation beats N Python-level ``in`` checks: the
        # scan happens entirely in C, and this runs on every field of every
        # record.  Empty rule sets get a pattern that never matches.
        self._triggers: re.Pattern[str] | None = (
            re.compile("|".join(re.escape(t) for t in triggers)) if triggers else None
        )
        self._field_names: frozenset[str] = SENSITIVE_FIELD_NAMES | {
            n.lower() for n in extra_field_names
        }

    # -- text ------------------------------------------------------------- #
    def _may_contain_secret(self, lowered: str) -> bool:
        return self._triggers is not None and self._triggers.search(lowered) is not None

    def mask_text(self, text: str) -> str:
        """Return ``text`` with every enabled pattern redacted."""
        if not self.enabled or not text:
            return text
        if len(text) > MAX_MASKABLE_LENGTH:
            # Mask the head (where headers/credentials realistically sit) and
            # drop the rest rather than running regexes over megabytes.
            head = self.mask_text(text[:MAX_MASKABLE_LENGTH])
            return f"{head}...[truncated {len(text) - MAX_MASKABLE_LENGTH} chars]"
        if not self._may_contain_secret(text.lower()):
            return text
        for pattern, replacement in self._compiled:
            text = pattern.sub(replacement, text)
        return text

    def contains_sensitive(self, text: str) -> bool:
        """True if any enabled pattern matches — used by security analytics."""
        if not text or not self._may_contain_secret(text.lower()):
            return False
        return any(pattern.search(text) for pattern, _ in self._compiled)

    # -- structured data --------------------------------------------------- #
    def mask_value(self, key: str, value: Any) -> Any:
        """Mask one key/value pair, recursing into nested containers."""
        if key.lower() in self._field_names:
            return REDACTED
        return self.mask_object(value)

    def mask_object(self, value: Any) -> Any:
        """Recursively mask an arbitrary JSON-like object."""
        if not self.enabled:
            return value
        if isinstance(value, str):
            return self.mask_text(value)
        if isinstance(value, Mapping):
            return {k: self.mask_value(str(k), v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            masked = [self.mask_object(v) for v in value]
            return type(value)(masked) if isinstance(value, (list, tuple)) else set(masked)
        return value

    def mask_mapping(self, data: Mapping[str, Any]) -> dict[str, Any]:
        """Mask a flat-or-nested mapping, returning a new ``dict``."""
        if not self.enabled:
            return dict(data)
        return {k: self.mask_value(str(k), v) for k, v in data.items()}


#: Process-wide default used by modules that have no access to configuration
#: (e.g. the logging filter installed before settings are loaded).
default_masker: Final[Masker] = Masker()


def mask_text(text: str) -> str:
    """Convenience wrapper around :data:`default_masker`."""
    return default_masker.mask_text(text)


__all__ = [
    "ALL_RULES",
    "DEFAULT_RULES",
    "REDACTED",
    "SENSITIVE_FIELD_NAMES",
    "Masker",
    "default_masker",
    "mask_text",
]
