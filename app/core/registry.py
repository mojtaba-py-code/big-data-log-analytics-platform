"""Generic plugin registry.

Responsibility
--------------
Every extension point in the platform — ingestion sources, parsers, storage
backends, anomaly detectors, cache backends — is discovered through one of
these.  New capabilities are added by registering a class, never by editing a
dispatch ``if/elif`` chain (open/closed principle).

Security note
-------------
Registration is **explicit**.  There is deliberately no "scan the filesystem
and import whatever looks like a plugin" mode: arbitrary-module import driven
by data is remote code execution waiting to happen.  Third-party plugins are
opted into via Python entry points, which requires the package to be installed
by an administrator.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Generic, TypeVar

from app.core.exceptions import PluginNotFoundError
from app.core.logging import get_logger

log = get_logger(__name__)

T = TypeVar("T")


class Registry(Generic[T]):
    """A name → factory mapping with decorator-based registration."""

    __slots__ = ("_aliases", "_items", "kind")

    def __init__(self, kind: str) -> None:
        self.kind = kind
        self._items: dict[str, type[T]] = {}
        self._aliases: dict[str, str] = {}

    # -- registration ------------------------------------------------------ #
    def register(
        self, name: str, *aliases: str, override: bool = False
    ) -> Callable[[type[T]], type[T]]:
        """Class decorator: ``@registry.register("nginx", "nginx-access")``."""

        def decorator(cls: type[T]) -> type[T]:
            self.add(name, cls, *aliases, override=override)
            return cls

        return decorator

    def add(self, name: str, cls: type[T], *aliases: str, override: bool = False) -> None:
        key = name.lower()
        if key in self._items and not override:
            raise ValueError(f"{self.kind} {name!r} is already registered")
        self._items[key] = cls
        for alias in aliases:
            self._aliases[alias.lower()] = key
        log.debug("registered %s plugin", self.kind, extra={"name": key, "impl": cls.__name__})

    # -- lookup ------------------------------------------------------------ #
    def resolve(self, name: str) -> type[T]:
        key = name.lower()
        key = self._aliases.get(key, key)
        try:
            return self._items[key]
        except KeyError as exc:
            raise PluginNotFoundError(
                f"unknown {self.kind} {name!r}",
                requested=name,
                available=sorted(self._items),
            ) from exc

    def create(self, name: str, /, *args: object, **kwargs: object) -> T:
        return self.resolve(name)(*args, **kwargs)

    def get(self, name: str, default: type[T] | None = None) -> type[T] | None:
        try:
            return self.resolve(name)
        except PluginNotFoundError:
            return default

    # -- introspection ----------------------------------------------------- #
    def names(self) -> list[str]:
        return sorted(self._items)

    def aliases(self) -> dict[str, str]:
        return dict(self._aliases)

    def describe(self) -> list[dict[str, str]]:
        """Human-facing listing used by ``loganalytics plugins``."""
        return [
            {
                "name": name,
                "implementation": f"{cls.__module__}.{cls.__qualname__}",
                "description": (cls.__doc__ or "").strip().splitlines()[0] if cls.__doc__ else "",
            }
            for name, cls in sorted(self._items.items())
        ]

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        key = name.lower()
        return self._aliases.get(key, key) in self._items

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._items))

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"<Registry {self.kind}: {', '.join(self.names())}>"


__all__ = ["Registry"]
