"""Safe filesystem access.

Responsibility
--------------
Every path that originates outside the process — a CLI argument, an API query
parameter, a filename inside an archive, a value from a config file — must pass
through :func:`resolve_within` before it is opened.

Threat model
------------
* **Path traversal** (``../../etc/shadow``): defeated by resolving the candidate
  and asserting the result is a descendant of an allow-listed root.
* **Symlink escape**: ``Path.resolve()`` follows symlinks, so a link pointing
  outside the root fails the containment check.  Symlinked *sources* are
  additionally rejected outright unless ``follow_symlinks`` is enabled.
* **Windows quirks**: ``resolve()`` normalises ``8.3`` short names, alternate
  data streams (``file.log:hidden``) are rejected, and reserved device names
  (``CON``, ``NUL``, ``COM1`` …) are rejected because opening them hangs or
  writes to hardware.
* **TOCTOU**: containment is re-checked by the caller at open time via
  :func:`open_stream`, which opens the *resolved* path only.
"""

from __future__ import annotations

import contextlib
import gzip
import io
import os
import re
import unicodedata
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import IO, Final, cast

from app.core.exceptions import PathTraversalError

#: Windows reserved device names (case-insensitive, with or without extension).
_WINDOWS_RESERVED: Final[frozenset[str]] = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

_UNSAFE_NAME_CHARS: Final[re.Pattern[str]] = re.compile(r'[\x00-\x1f<>:"|?*\\/]')

#: Both path separators, so traversal is detected the same way on POSIX and NT.
_SEPARATORS: Final[re.Pattern[str]] = re.compile(r"[\\/]")


def is_within(candidate: Path, root: Path) -> bool:
    """True when ``candidate`` is ``root`` itself or lives beneath it."""
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def resolve_within(
    candidate: str | Path,
    roots: Sequence[Path] | Path,
    *,
    must_exist: bool = False,
    allow_symlinks: bool = False,
) -> Path:
    """Resolve ``candidate`` and assert it lives under one of ``roots``.

    Raises
    ------
    PathTraversalError
        If the resolved path escapes every root, or trips a platform guard.
    """
    root_list = [roots] if isinstance(roots, Path) else list(roots)
    if not root_list:
        raise PathTraversalError("no permitted roots configured")

    raw = str(candidate)
    if "\x00" in raw:
        raise PathTraversalError("path contains a NUL byte")

    # ``Path.resolve()`` only understands the *native* separator, so on POSIX a
    # Windows-style "..\\..\\etc" is a single odd filename that lands inside the
    # root and slips past the containment check below.  Rejecting a literal
    # parent segment under either separator makes traversal fail identically on
    # every platform — which matters because ingestion accepts paths that
    # originate on Windows hosts but runs on Linux.
    if any(segment == ".." for segment in _SEPARATORS.split(raw)):
        raise PathTraversalError("path contains a parent-directory segment", path=raw)

    path = Path(raw).expanduser()
    if not allow_symlinks:
        try:
            is_link = path.is_symlink()
        except OSError:
            # ``lstat`` on a protected path (Windows raises PermissionError on
            # e.g. C:\Windows\System32\config\SAM) must not abort the check —
            # the containment test below is what actually rejects it.
            is_link = False
        if is_link:
            raise PathTraversalError("symlinked paths are not permitted", path=raw)

    resolved = path.resolve()
    _reject_platform_hazards(resolved)

    resolved_roots = [r.expanduser().resolve() for r in root_list]
    if not any(is_within(resolved, root) for root in resolved_roots):
        # The message deliberately omits the roots: telling an attacker which
        # directories are allowed is free reconnaissance.
        raise PathTraversalError(
            "path is outside the permitted roots",
            path=raw,
        )

    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"no such file or directory: {resolved}")
    return resolved


def _reject_platform_hazards(path: Path) -> None:
    for part in path.parts:
        stem = part.split(".", 1)[0].upper().rstrip(" .")
        if stem in _WINDOWS_RESERVED:
            raise PathTraversalError("path refers to a reserved device name", part=part)
    # NTFS alternate data streams:  "logs.txt:secret".  ``C:\`` is exempt.
    tail = path.name
    if ":" in tail:
        raise PathTraversalError("path contains an alternate data stream", part=tail)


def safe_filename(name: str, *, fallback: str = "unnamed", max_length: int = 180) -> str:
    """Sanitise an externally supplied *file name* (never a path).

    Used when a filename is derived from user input — e.g. a report name or a
    remote ``Content-Disposition`` header.
    """
    name = unicodedata.normalize("NFKC", name).strip()
    name = _UNSAFE_NAME_CHARS.sub("_", name).strip(" .")
    if not name or name.upper().split(".", 1)[0] in _WINDOWS_RESERVED:
        return fallback
    if len(name) > max_length:
        stem, dot, suffix = name.rpartition(".")
        if dot and len(suffix) <= 10:
            keep = max_length - len(suffix) - 1
            name = f"{stem[:keep]}.{suffix}"
        else:
            name = name[:max_length]
    return name


def ensure_directory(path: Path, *, mode: int = 0o750) -> Path:
    """Create ``path`` (and parents) with least-privilege permissions."""
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":  # POSIX-only; Windows ignores the mode bits anyway
        with contextlib.suppress(OSError):  # e.g. a read-only mounted volume
            path.chmod(mode)
    return path


def open_stream(
    path: Path,
    *,
    encoding: str = "utf-8",
    errors: str = "replace",
    max_bytes: int | None = None,
) -> IO[str]:
    """Open a (optionally gzipped) text file for streaming reads.

    ``max_bytes`` guards against decompression bombs: a 1 MB ``.gz`` can expand
    to many gigabytes, so the *decompressed* stream is capped, not the file.
    """
    binary: IO[bytes]
    if path.suffix.lower() == ".gz":
        # GzipFile satisfies the binary IO protocol; the annotation is what
        # lets the two branches share one variable.
        binary = cast("IO[bytes]", gzip.open(path, "rb"))  # noqa: SIM115 - caller closes
    else:
        binary = path.open("rb")
    if max_bytes is not None:
        binary = _BoundedReader(binary, max_bytes)  # type: ignore[assignment]
    return io.TextIOWrapper(binary, encoding=encoding, errors=errors, newline="")


class _BoundedReader(io.RawIOBase):
    """Wraps a binary stream and refuses to yield more than ``limit`` bytes."""

    def __init__(self, stream: IO[bytes], limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self._read = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: memoryview) -> int:  # type: ignore[override]
        remaining = self._limit - self._read
        if remaining <= 0:
            return 0
        chunk = self._stream.read(min(len(buffer), remaining))
        if not chunk:
            return 0
        self._read += len(chunk)
        buffer[: len(chunk)] = chunk
        return len(chunk)

    def close(self) -> None:
        try:
            self._stream.close()
        finally:
            super().close()

    @property
    def bytes_read(self) -> int:
        return self._read


def iter_files(
    root: Path,
    patterns: Iterable[str] = ("*.log", "*.txt", "*.csv", "*.json", "*.jsonl", "*.gz"),
    *,
    recursive: bool = True,
    follow_symlinks: bool = False,
) -> list[Path]:
    """List matching files beneath ``root``, sorted for deterministic runs."""
    if not root.is_dir():
        return []
    found: set[Path] = set()
    for pattern in patterns:
        glob_pattern = f"**/{pattern}" if recursive else pattern
        for candidate in root.glob(glob_pattern):
            if not candidate.is_file():
                continue
            if candidate.is_symlink() and not follow_symlinks:
                continue
            found.add(candidate)
    return sorted(found)


__all__ = [
    "ensure_directory",
    "is_within",
    "iter_files",
    "open_stream",
    "resolve_within",
    "safe_filename",
]
