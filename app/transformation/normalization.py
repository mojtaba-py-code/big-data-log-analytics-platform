"""Schema and value normalisation.

Responsibility
--------------
Make records from different sources *comparable*.  Parsing produces correct
records; normalisation makes ``payment-api``, ``Payment_API`` and
``payment.api`` the same service, and turns

    /api/v1/users/8f2c1e40-.../orders/9931

into

    /api/v1/users/{uuid}/orders/{id}

Why endpoint templating matters
-------------------------------
Without it, "top endpoints" degenerates into a list of a million distinct URLs
and every per-endpoint latency percentile is computed over a single sample.
Templating is what makes HTTP analytics meaningful — and it also stops raw
identifiers (order ids, e-mail addresses in path segments) from being
materialised into aggregate tables.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from typing import Final

from app.models.enums import Environment
from app.models.log_event import LogEvent

_SERVICE_CLEAN: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9]+")

_UUID: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_HEX: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{16,64}$", re.IGNORECASE)
_NUMERIC: Final[re.Pattern[str]] = re.compile(r"^\d{1,19}$")
_EMAILISH: Final[re.Pattern[str]] = re.compile(r"^[^@/]{1,64}@[^@/]{1,255}$")
_VERSION: Final[re.Pattern[str]] = re.compile(r"^v\d{1,3}$", re.IGNORECASE)
#: Mixed alphanumeric tokens (session keys, slugs with ids) — long ones only,
#: so genuine path words like ``checkout2`` are not templated away.
_MIXED_ID: Final[re.Pattern[str]] = re.compile(r"^(?=.{12,64}$)(?=.*\d)[A-Za-z0-9_\-]+$")

MAX_PATH_SEGMENTS: Final[int] = 24

_ENV_SUFFIXES: Final[dict[str, Environment]] = {
    "prod": Environment.PRODUCTION,
    "production": Environment.PRODUCTION,
    "live": Environment.PRODUCTION,
    "stg": Environment.STAGING,
    "stage": Environment.STAGING,
    "staging": Environment.STAGING,
    "uat": Environment.STAGING,
    "dev": Environment.DEVELOPMENT,
    "develop": Environment.DEVELOPMENT,
    "development": Environment.DEVELOPMENT,
    "local": Environment.DEVELOPMENT,
    "test": Environment.TEST,
    "qa": Environment.TEST,
}

#: Ordered so the most specific family wins (``Edg`` before ``Chrome``, which
#: itself must be tested before ``Safari`` — Chrome's UA string contains both).
_UA_FAMILIES: Final[tuple[tuple[str, str], ...]] = (
    ("edg", "Edge"),
    ("opr", "Opera"),
    ("chrome", "Chrome"),
    ("firefox", "Firefox"),
    ("safari", "Safari"),
    ("msie", "IE"),
    ("trident", "IE"),
    ("curl", "curl"),
    ("wget", "wget"),
    ("python-requests", "python-requests"),
    ("httpie", "HTTPie"),
    ("postman", "Postman"),
    ("go-http-client", "Go"),
    ("java", "Java"),
    ("okhttp", "OkHttp"),
    ("bot", "Bot"),
    ("crawler", "Bot"),
    ("spider", "Bot"),
)


def normalise_service(name: str | None) -> str | None:
    """``Payment_API`` / ``payment.api`` → ``payment-api``."""
    if not name:
        return None
    slug = _SERVICE_CLEAN.sub("-", name.strip().lower()).strip("-")
    return slug[:255] or None


def normalise_hostname(host: str | None) -> str | None:
    """Lower-case, strip trailing dot and any port suffix."""
    if not host:
        return None
    text = host.strip().lower().rstrip(".")
    if text.count(":") == 1 and not text.startswith("["):
        text = text.split(":", 1)[0]
    return text[:255] or None


def infer_environment(*hints: str | None) -> Environment:
    """Guess the deployment environment from hostnames / service names."""
    for hint in hints:
        if not hint:
            continue
        for token in re.split(r"[^a-z0-9]+", hint.lower()):
            env = _ENV_SUFFIXES.get(token)
            if env is not None:
                return env
    return Environment.UNKNOWN


def template_endpoint(path: str | None, *, max_segments: int = MAX_PATH_SEGMENTS) -> str | None:
    """Replace identifier-looking path segments with typed placeholders."""
    if not path:
        return None
    if not path.startswith("/"):
        path = "/" + path
    segments = path.split("/")[: max_segments + 1]
    out: list[str] = []
    for segment in segments:
        if not segment:
            out.append(segment)
            continue
        if _VERSION.match(segment):
            out.append(segment.lower())
        elif _UUID.match(segment):
            out.append("{uuid}")
        elif _NUMERIC.match(segment):
            out.append("{id}")
        elif _HEX.match(segment):
            out.append("{hash}")
        elif _EMAILISH.match(segment):
            out.append("{email}")
        elif _MIXED_ID.match(segment):
            out.append("{token}")
        else:
            out.append(segment.lower()[:64])
    templated = "/".join(out) or "/"
    if len(templated) > 1 and templated.endswith("/"):
        templated = templated.rstrip("/")
    return templated or "/"


def user_agent_family(user_agent: str | None) -> str | None:
    """Coarse client family — enough for analytics, no fingerprinting."""
    if not user_agent:
        return None
    lowered = user_agent.lower()
    for needle, family in _UA_FAMILIES:
        if needle in lowered:
            return family
    return "Other"


def classify_ip(ip: str | None) -> str | None:
    """``loopback`` / ``private`` / ``public`` / ``reserved``.

    Used by security analytics: a brute-force attempt from a private RFC1918
    address is a very different signal from the same pattern off the internet.
    """
    if not ip:
        return None
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if address.is_loopback:
        return "loopback"
    if address.is_private:
        return "private"
    if address.is_reserved or address.is_multicast or address.is_link_local:
        return "reserved"
    return "public"


class RecordNormalizer:
    """Applies every normalisation rule to a :class:`LogEvent`."""

    def __init__(
        self,
        *,
        template_endpoints: bool = True,
        infer_environment_from_host: bool = True,
        default_service: str | None = None,
    ) -> None:
        self.template_endpoints = template_endpoints
        self.infer_environment_from_host = infer_environment_from_host
        self.default_service = normalise_service(default_service)

    def normalise(self, event: LogEvent) -> LogEvent:
        updates: dict[str, object] = {}
        metadata = dict(event.metadata)

        service = normalise_service(event.service) or self.default_service
        if service != event.service:
            updates["service"] = service

        hostname = normalise_hostname(event.hostname)
        if hostname != event.hostname:
            updates["hostname"] = hostname

        if self.infer_environment_from_host and event.environment is Environment.UNKNOWN:
            inferred = infer_environment(hostname, service, event.source)
            if inferred is not Environment.UNKNOWN:
                updates["environment"] = inferred

        if self.template_endpoints and event.endpoint:
            templated = template_endpoint(event.endpoint)
            if templated and templated != event.endpoint:
                # Both are kept: the template drives aggregation, the raw path
                # stays available for incident forensics.
                metadata["endpoint_raw"] = event.endpoint
                updates["endpoint"] = templated

        family = user_agent_family(event.user_agent)
        if family:
            metadata["ua_family"] = family
        ip_class = classify_ip(event.ip_address)
        if ip_class:
            metadata["ip_class"] = ip_class

        if metadata != event.metadata:
            updates["metadata"] = metadata
        if not updates:
            return event
        return event.model_copy(update=updates)

    def normalise_many(self, events: Iterable[LogEvent]) -> Iterable[LogEvent]:
        for event in events:
            yield self.normalise(event)


__all__ = [
    "RecordNormalizer",
    "classify_ip",
    "infer_environment",
    "normalise_hostname",
    "normalise_service",
    "template_endpoint",
    "user_agent_family",
]
