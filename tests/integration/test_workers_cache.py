"""Cache backend and background-worker tests."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from app.cache import INGEST_SENSITIVE_PREFIXES, cached, invalidate_after_ingest
from app.cache.backends import CacheStats, MemoryCache, RedisCache, build_cache
from app.core.config import CacheSettings, Settings
from app.models.enums import JobStatus
from app.workers.queue import JobQueue, available_jobs, register_job

pytestmark = pytest.mark.integration


class TestMemoryCache:
    def test_get_set_and_miss(self) -> None:
        cache = MemoryCache()
        key = cache.build_key("analytics", "a", 1)
        assert cache.get(key) is None
        cache.set(key, {"value": 42})
        assert cache.get(key) == {"value": 42}
        assert cache.stats.hits == 1
        assert cache.stats.misses == 1

    def test_entries_expire(self) -> None:
        cache = MemoryCache(default_ttl=1)
        cache.set("k", "v", ttl=0)
        time.sleep(0.01)
        assert cache.get("k") is None

    def test_lru_eviction_is_bounded(self) -> None:
        cache = MemoryCache(max_entries=16)
        for index in range(100):
            cache.set(f"k{index}", index)
        assert len(cache) == 16
        assert cache.stats.evictions > 0

    def test_clear_by_prefix(self) -> None:
        cache = MemoryCache(namespace="ns")
        cache.set(cache.build_key("analytics", "x"), 1)
        cache.set(cache.build_key("reports", "y"), 2)
        assert cache.clear("analytics") == 1
        assert len(cache) == 1

    def test_clear_everything(self) -> None:
        cache = MemoryCache()
        cache.set("a", 1)
        cache.set("b", 2)
        assert cache.clear() == 2

    def test_keys_do_not_contain_user_input(self) -> None:
        cache = MemoryCache()
        key = cache.build_key("search", "'; DROP TABLE logs; --")
        assert "DROP" not in key
        assert key.startswith("loga:search:")

    def test_distinct_arguments_produce_distinct_keys(self) -> None:
        cache = MemoryCache()
        assert cache.build_key("a", 1) != cache.build_key("a", 2)

    def test_get_or_set_computes_once(self) -> None:
        cache = MemoryCache()
        calls = {"n": 0}

        def factory() -> int:
            calls["n"] += 1
            return 7

        assert cache.get_or_set("k", factory) == 7
        assert cache.get_or_set("k", factory) == 7
        assert calls["n"] == 1

    def test_decorator_memoises(self) -> None:
        cache = MemoryCache()
        calls = {"n": 0}

        @cached(cache, "analytics")
        def expensive(value: int) -> int:
            calls["n"] += 1
            return value * 2

        assert expensive(21) == 42
        assert expensive(21) == 42
        assert calls["n"] == 1

    def test_invalidation_after_ingest_clears_the_right_prefixes(self) -> None:
        cache = MemoryCache()
        for prefix in INGEST_SENSITIVE_PREFIXES:
            cache.set(cache.build_key(prefix, "x"), 1)
        cache.set(cache.build_key("other", "x"), 1)
        assert invalidate_after_ingest(cache) == len(INGEST_SENSITIVE_PREFIXES)
        assert len(cache) == 1

    def test_health_reports_stats(self) -> None:
        cache = MemoryCache()
        cache.set("a", 1)
        cache.get("a")
        health = cache.health()
        assert health["healthy"] is True
        assert health["hit_rate"] == 1.0

    def test_stats_hit_rate_with_no_traffic(self) -> None:
        assert CacheStats().hit_rate == 0.0


class TestRedisCache:
    @pytest.fixture
    def redis_cache(self):  # noqa: ANN201
        fakeredis = pytest.importorskip("fakeredis")
        return RedisCache(
            "redis://localhost:6379/0",
            client=fakeredis.FakeRedis(decode_responses=True),
        )

    def test_round_trip(self, redis_cache: RedisCache) -> None:
        redis_cache.set("k", {"a": 1})
        assert redis_cache.get("k") == {"a": 1}

    def test_missing_key(self, redis_cache: RedisCache) -> None:
        assert redis_cache.get("absent") is None

    def test_delete(self, redis_cache: RedisCache) -> None:
        redis_cache.set("k", 1)
        redis_cache.delete("k")
        assert redis_cache.get("k") is None

    def test_clear_by_prefix_uses_scan(self, redis_cache: RedisCache) -> None:
        redis_cache.set(redis_cache.build_key("analytics", "a"), 1)
        redis_cache.set(redis_cache.build_key("reports", "b"), 2)
        assert redis_cache.clear("analytics") == 1

    def test_corrupt_entries_are_treated_as_misses(self, redis_cache: RedisCache) -> None:
        redis_cache._client.set("bad", "{not json")
        assert redis_cache.get("bad") is None

    def test_unserialisable_values_are_skipped(self, redis_cache: RedisCache) -> None:
        # ``default=str`` copes with exotic scalars, so the genuinely
        # unserialisable case is a cycle.
        circular: dict[str, Any] = {}
        circular["self"] = circular
        redis_cache.set("k", circular)
        assert redis_cache.get("k") is None

    def test_outage_degrades_to_a_miss(self) -> None:
        class BrokenClient:
            def get(self, *_: object) -> None:
                raise ConnectionError("redis is down")

            def setex(self, *_: object) -> None:
                raise ConnectionError("redis is down")

            def ping(self) -> bool:
                raise ConnectionError("redis is down")

            def close(self) -> None:
                pass

        cache = RedisCache("redis://x", client=BrokenClient())
        assert cache.get("k") is None  # no exception escapes
        cache.set("k", 1)
        assert cache.health()["healthy"] is False
        assert cache.stats.errors > 0

    def test_values_are_json_not_pickle(self, redis_cache: RedisCache) -> None:
        redis_cache.set("k", {"a": 1})
        assert json.loads(redis_cache._client.get("k")) == {"a": 1}


class TestCacheFactory:
    def test_memory_backend(self) -> None:
        assert isinstance(build_cache(CacheSettings(backend="memory")), MemoryCache)

    def test_unreachable_redis_falls_back_to_memory(self) -> None:
        settings = CacheSettings(backend="redis", redis_host="127.0.0.1", redis_port=1)
        assert isinstance(build_cache(settings), MemoryCache)


@register_job("_test_echo")
def _echo_job(value: int = 1) -> dict[str, int]:
    return {"value": value}


@register_job("_test_boom")
def _boom_job() -> None:
    raise RuntimeError("intentional failure")


class TestJobQueue:
    @pytest.fixture
    def queue(self):  # noqa: ANN201
        q = JobQueue(concurrency=2, default_max_retries=0, retry_backoff_seconds=0.001)
        yield q
        q.shutdown(wait=False)

    def test_registered_jobs_are_discoverable(self) -> None:
        assert "_test_echo" in available_jobs()
        assert "ingest" in available_jobs()

    def test_job_runs_and_reports_a_result(self, queue: JobQueue) -> None:
        job = queue.submit("_test_echo", value=5)
        finished = queue.wait(job.id, timeout=10)
        assert finished is not None
        assert finished.status is JobStatus.SUCCEEDED
        assert finished.result == {"value": 5}
        assert finished.duration_seconds is not None

    def test_failure_is_recorded_not_raised(self, queue: JobQueue) -> None:
        job = queue.submit("_test_boom")
        finished = queue.wait(job.id, timeout=10)
        assert finished is not None
        assert finished.status is JobStatus.FAILED
        assert "intentional failure" in (finished.error or "")

    def test_retries_are_attempted(self) -> None:
        queue = JobQueue(concurrency=1, default_max_retries=2, retry_backoff_seconds=0.001)
        try:
            job = queue.submit("_test_boom")
            finished = queue.wait(job.id, timeout=10)
            assert finished is not None
            assert finished.attempts == 3
        finally:
            queue.shutdown(wait=False)

    def test_unknown_job_is_rejected(self, queue: JobQueue) -> None:
        from app.core.exceptions import JobError

        with pytest.raises(JobError):
            queue.submit("does_not_exist")

    def test_listing_and_stats(self, queue: JobQueue) -> None:
        job = queue.submit("_test_echo")
        queue.wait(job.id, timeout=10)
        assert any(entry.id == job.id for entry in queue.list())
        stats = queue.stats()
        assert stats["tracked"] >= 1
        assert "_test_echo" in stats["registered_jobs"]

    def test_history_is_bounded(self) -> None:
        queue = JobQueue(concurrency=1, max_history=10, default_max_retries=0)
        try:
            for _ in range(25):
                job = queue.submit("_test_echo")
                queue.wait(job.id, timeout=10)
            assert len(queue.list(limit=1_000)) <= 11
        finally:
            queue.shutdown(wait=False)

    def test_serialised_job_view_is_compact(self, queue: JobQueue) -> None:
        job = queue.submit("_test_echo")
        queue.wait(job.id, timeout=10)
        payload = queue.get(job.id).as_dict()
        assert set(payload) >= {"id", "name", "status", "attempts", "result"}

    def test_submission_after_shutdown_is_rejected(self) -> None:
        from app.core.exceptions import JobError

        queue = JobQueue(concurrency=1)
        queue.shutdown(wait=False)
        with pytest.raises(JobError):
            queue.submit("_test_echo")


class TestRegisteredJobs:
    def test_generate_then_ingest_then_report(
        self, settings: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.core.config import get_settings
        from app.workers import jobs

        monkeypatch.setattr("app.workers.jobs.get_settings", lambda: settings)
        get_settings.cache_clear()

        generated = jobs.generate_data_job(count=300, filename="job.log")
        assert generated["records"] == 300

        ingested = jobs.ingest_job(source=generated["path"])
        assert ingested["records_written"] > 0

        report = jobs.report_job(hours=48)
        assert Path(report["path"]).exists()

        anomalies = jobs.detect_anomalies_job(hours=48, window="15m")
        assert "anomalies" in anomalies

        security = jobs.security_scan_job(hours=48)
        assert "findings" in security

    def test_cleanup_defaults_to_a_dry_run(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch, populated_store: Path
    ) -> None:
        from app.workers import jobs

        monkeypatch.setattr("app.workers.jobs.get_settings", lambda: settings)
        result = jobs.cleanup_job(retention_days=0, layer="processed")
        assert result["dry_run"] is True
        assert list(settings.processed_path.rglob("*.parquet"))  # nothing deleted

    def test_cleanup_removes_old_partitions_when_asked(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch, populated_store: Path
    ) -> None:
        from app.workers import jobs

        monkeypatch.setattr("app.workers.jobs.get_settings", lambda: settings)
        result = jobs.cleanup_job(retention_days=0, layer="processed", dry_run=False)
        assert result["partitions_removed"] >= 1
        assert not list(settings.processed_path.rglob("*.parquet"))

    def test_cleanup_rejects_an_unknown_layer(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.workers import jobs

        monkeypatch.setattr("app.workers.jobs.get_settings", lambda: settings)
        with pytest.raises(ValueError, match="unknown layer"):
            jobs.cleanup_job(layer="nowhere")

    def test_compact_merges_small_files(
        self, settings: Settings, monkeypatch: pytest.MonkeyPatch, sample_events
    ) -> None:
        from app.storage import ParquetStore
        from app.workers import jobs

        for index in range(3):
            store = ParquetStore(settings.processed_path)
            store.write(sample_events[:20], run_id=f"r{index}")
            store.flush()
        monkeypatch.setattr("app.workers.jobs.get_settings", lambda: settings)
        result = jobs.compact_job(layer="processed")
        assert result["files_compacted"] >= 2
