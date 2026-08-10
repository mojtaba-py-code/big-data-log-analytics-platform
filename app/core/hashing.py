"""Deterministic hashing helpers.

Two very different needs live here, and conflating them is a classic bug:

* **Fingerprints** (:func:`fingerprint`, :func:`event_id_for`) must be *stable
  across processes and runs* — Python's ``hash()`` is salted per interpreter and
  is therefore unusable for de-duplication or idempotent IDs.  BLAKE2b is used:
  it is faster than SHA-256 on the CPython hot path and lets us pick a short
  digest size.
* **Credential hashing** (:func:`hash_secret`, :func:`verify_secret`) must be
  constant-time on comparison.  SHA-256 over a high-entropy API key is
  appropriate here (the key is random, so no work factor is needed); user
  *passwords* would require Argon2/bcrypt instead and are out of scope.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterable, Mapping
from typing import Any, Final

#: 16 bytes → 32 hex chars.  At 10^10 events the collision probability is
#: ~10^-18, which is far below the platform's own error rate.
FINGERPRINT_DIGEST_SIZE: Final[int] = 16

_NULL = "\x1f"  # unit separator: cannot appear in a normalised field value


def _canonical(value: Any) -> str:
    """Render a value into a stable string form.

    ``None`` and the empty string must *not* collide, otherwise a record with a
    missing service would de-duplicate against one with ``service=""``.
    """
    if value is None:
        return "\x00none"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        # repr() round-trips and avoids locale-dependent formatting.
        return repr(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical(v) for v in value) + "]"
    if isinstance(value, Mapping):
        return "{" + ",".join(f"{k}={_canonical(v)}" for k, v in sorted(value.items())) + "}"
    return str(value)


def fingerprint(values: Iterable[Any], *, digest_size: int = FINGERPRINT_DIGEST_SIZE) -> str:
    """Stable hex fingerprint of an ordered sequence of values.

    Built as one joined string and hashed once.  Incremental ``update()`` calls
    would be tidier but cost an extra encode and C call per value, and this
    runs on every ingested record.
    """
    joined = _NULL.join(_canonical(value) for value in values)
    return hashlib.blake2b(
        joined.encode("utf-8", "surrogatepass"), digest_size=digest_size
    ).hexdigest()


def fingerprint_fields(record: Mapping[str, Any], fields: Iterable[str]) -> str:
    """Fingerprint a mapping over an explicit, ordered field list.

    The field *names* are folded in as well, so changing the configured
    de-duplication key set cannot silently produce colliding fingerprints
    against data written under the previous configuration.
    """
    field_list = list(fields)
    parts: list[Any] = []
    for name in field_list:
        parts.append(name)
        parts.append(record.get(name))
    return fingerprint(parts)


def content_hash(text: str, *, digest_size: int = FINGERPRINT_DIGEST_SIZE) -> str:
    """Fingerprint of a single string (e.g. a raw log line)."""
    return hashlib.blake2b(
        text.encode("utf-8", "surrogatepass"), digest_size=digest_size
    ).hexdigest()


def event_id_for(*parts: Any) -> str:
    """Derive a deterministic event id.

    Determinism is what makes the whole pipeline **idempotent**: re-ingesting
    the same file produces the same ids, so a re-run after a crash overwrites
    rather than duplicates.
    """
    return fingerprint(parts)


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #
def hash_secret(secret: str) -> str:
    """Hash a high-entropy secret (API key) for storage/comparison."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_secret(candidate: str, expected_hash: str) -> bool:
    """Constant-time comparison of a presented secret against a stored hash.

    ``compare_digest`` is essential: a short-circuiting ``==`` leaks the shared
    prefix length through timing and makes key recovery tractable.
    """
    return hmac.compare_digest(hash_secret(candidate), expected_hash.strip().lower())


def generate_api_key(nbytes: int = 32) -> str:
    """Generate a new URL-safe API key from the OS CSPRNG."""
    return secrets.token_urlsafe(nbytes)


__all__ = [
    "FINGERPRINT_DIGEST_SIZE",
    "content_hash",
    "event_id_for",
    "fingerprint",
    "fingerprint_fields",
    "generate_api_key",
    "hash_secret",
    "verify_secret",
]
