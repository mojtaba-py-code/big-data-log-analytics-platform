"""Administrative endpoints.

All require the ``admin`` scope.  Note what is *absent*: there is no endpoint
that returns raw configuration, no endpoint that runs a command, and no
endpoint that returns a plaintext API key.  ``GET /admin/config`` returns the
Pydantic dump, in which every secret is already a ``SecretStr`` and therefore
renders as ``**********``.
"""

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel, ConfigDict, Field

from app.api.deps import get_cache, reset_dependencies
from app.api.security import (
    Principal,
    RequireAdmin,
    clear_principal_cache,
    require_scope,
)
from app.cache import CacheBackend, invalidate_after_ingest
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.storage import MetadataStore
from app.validation.dlq import rejection_stats

log = get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[RequireAdmin])


class ApiKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9_.\-]+$")
    scopes: list[str] = Field(default_factory=lambda: ["read"])


@router.get("/config", summary="Effective configuration (secrets redacted)")
async def config(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, Any]:
    """The running configuration, with every secret redacted by the model."""
    return settings.safe_dump()


@router.get("/plugins", summary="Registered plugins")
async def plugins() -> dict[str, Any]:
    """Every registered parser, source, storage backend and detector."""
    from app.anomaly_detection.detectors import anomaly_registry
    from app.cache.backends import cache_registry
    from app.deduplication.strategies import dedup_registry
    from app.ingestion.base import source_registry
    from app.parsers.base import parser_registry
    from app.storage.base import storage_registry
    from app.workers.queue import available_jobs

    return {
        "parsers": parser_registry.describe(),
        "sources": source_registry.describe(),
        "storage": storage_registry.describe(),
        "deduplication": dedup_registry.describe(),
        "anomaly_detectors": anomaly_registry.describe(),
        "cache_backends": cache_registry.describe(),
        "jobs": available_jobs(),
    }


@router.get("/runs", summary="Recent pipeline runs")
async def runs(
    settings: Annotated[Settings, Depends(get_settings)],
    limit: Annotated[int, Query(ge=1, le=200)] = 20,
) -> dict[str, Any]:
    store = MetadataStore.from_settings(settings)
    store.create_schema()
    try:
        return {"runs": store.recent_runs(limit), "stats": store.run_stats()}
    finally:
        store.close()


@router.get("/rejected", summary="Dead-letter queue statistics")
async def rejected(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, Any]:
    """Rejection counts by reason — the data-quality dashboard's source."""
    counts = rejection_stats(settings.rejected_path)
    return {"total": sum(counts.values()), "by_reason": counts}


@router.post("/cache/clear", summary="Invalidate cached analytics")
async def clear_cache(
    cache: Annotated[CacheBackend, Depends(get_cache)],
    prefix: Annotated[str | None, Query(max_length=64)] = None,
) -> dict[str, Any]:
    removed = cache.clear(prefix) if prefix else invalidate_after_ingest(cache)
    return {"cleared": removed, "prefix": prefix}


@router.get("/cache/stats", summary="Cache statistics")
async def cache_stats(cache: Annotated[CacheBackend, Depends(get_cache)]) -> dict[str, Any]:
    return cache.health()


@router.post("/reload", summary="Reload configuration and rebuild dependencies")
async def reload_config(
    principal: Annotated[Principal, Depends(require_scope("admin"))],
) -> dict[str, Any]:
    """Re-read configuration and drop cached collaborators.

    Cheaper than a restart for a config change, and safe because every
    dependency is rebuilt lazily on the next request.
    """
    from app.api.security import clear_principal_cache
    from app.core.config import reset_settings_cache

    reset_settings_cache()
    reset_dependencies()
    clear_principal_cache()  # revoked keys stop working immediately
    log.info("configuration reloaded", extra={"principal": principal.name})
    return {"reloaded": True}


@router.get("/apikeys", summary="List API keys (hashes only)")
async def list_api_keys(settings: Annotated[Settings, Depends(get_settings)]) -> dict[str, Any]:
    store = MetadataStore.from_settings(settings)
    store.create_schema()
    try:
        return {"keys": store.list_api_keys()}
    finally:
        store.close()


@router.post("/apikeys", summary="Create an API key", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    settings: Annotated[Settings, Depends(get_settings)],
    principal: Annotated[Principal, Depends(require_scope("admin"))],
    request: Annotated[ApiKeyRequest, Body()],
) -> dict[str, Any]:
    """Mint a key.

    The plaintext is returned **once** and is not recoverable afterwards: only
    its hash is stored.  A leaked database therefore yields no usable keys.
    """
    invalid = sorted(set(request.scopes) - {"read", "write", "admin"})
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unknown scopes: {', '.join(invalid)}",
        )
    store = MetadataStore.from_settings(settings)
    store.create_schema()
    try:
        secret = store.create_api_key(request.name, request.scopes)
    finally:
        store.close()
    log.info(
        "api key created via API",
        extra={"key_name": request.name, "principal": principal.name},
    )
    return {
        "name": request.name,
        "scopes": request.scopes,
        "api_key": secret,
        "warning": "This key is shown only once. Store it securely.",
    }


@router.delete("/apikeys/{name}", summary="Revoke an API key")
async def revoke_api_key(
    settings: Annotated[Settings, Depends(get_settings)],
    principal: Annotated[Principal, Depends(require_scope("admin"))],
    name: Annotated[str, Path(max_length=128, pattern=r"^[A-Za-z0-9_.\-]+$")],
) -> dict[str, Any]:
    store = MetadataStore.from_settings(settings)
    store.create_schema()
    try:
        revoked = store.revoke_api_key(name)
    finally:
        store.close()
    if not revoked:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="key not found")
    # Without this, the revoked key would keep working until its cached
    # principal expired.
    clear_principal_cache()
    log.info("api key revoked", extra={"key_name": name, "principal": principal.name})
    return {"revoked": name}


__all__ = ["router"]
