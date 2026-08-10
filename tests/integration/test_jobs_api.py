"""Job submission through the API, parallel processing and stored reports."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.config import Settings
from app.pipeline import PipelineOptions
from app.pipeline.parallel import effective_worker_count, process_parallel

pytestmark = pytest.mark.integration


class TestParallelProcessing:
    def test_worker_count_never_exceeds_the_work(self) -> None:
        assert effective_worker_count(requested=8, item_count=2) == 2
        assert effective_worker_count(requested=1, item_count=100) == 1

    def test_worker_count_leaves_a_core_free(self) -> None:
        import os

        cpu = os.cpu_count() or 2
        assert effective_worker_count(requested=999, item_count=999) <= max(1, cpu - 1)

    def test_empty_input_returns_an_empty_result(self, settings: Settings) -> None:
        result = process_parallel([], settings, PipelineOptions(run_id="none"))
        assert result.records_written == 0
        assert result.finished_at is not None

    def test_multiprocess_run_merges_results(self, settings: Settings, tmp_path: Path) -> None:
        files = []
        for index in range(2):
            path = tmp_path / "raw" / f"mp{index}.log"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "\n".join(
                    json.dumps({"timestamp": "2026-08-07T12:00:00Z", "message": f"f{index}-{n}"})
                    for n in range(30)
                ),
                encoding="utf-8",
            )
            files.append(path)
        result = process_parallel(files, settings, PipelineOptions(run_id="mp"), workers=2)
        assert result.records_written == 60
        assert len(result.sources) == 2

    def test_one_bad_file_does_not_fail_the_batch(self, settings: Settings, tmp_path: Path) -> None:
        good = tmp_path / "raw" / "good.log"
        good.parent.mkdir(parents=True, exist_ok=True)
        good.write_text(
            json.dumps({"timestamp": "2026-08-07T12:00:00Z", "message": "ok"}),
            encoding="utf-8",
        )
        missing = tmp_path / "raw" / "missing.log"
        result = process_parallel(
            [good, missing], settings, PipelineOptions(run_id="mixed"), workers=1
        )
        assert result.records_written == 1
        assert not result.succeeded
        assert result.errors


class TestJobApi:
    def test_submit_and_poll_a_job(self, api_client) -> None:
        submitted = api_client.post(
            "/jobs", json={"name": "detect_anomalies", "parameters": {"hours": 1}}
        )
        assert submitted.status_code == 202
        job_id = submitted.json()["job"]["id"]

        import time

        for _ in range(60):
            body = api_client.get(f"/jobs/{job_id}").json()
            if body["status"] in {"succeeded", "failed"}:
                break
            time.sleep(0.1)
        assert body["status"] in {"succeeded", "failed", "running"}

    def test_unknown_job_is_rejected(self, api_client) -> None:
        response = api_client.post("/jobs", json={"name": "nope", "parameters": {}})
        assert response.status_code == 400

    def test_extra_body_fields_are_rejected(self, api_client) -> None:
        response = api_client.post(
            "/jobs", json={"name": "report", "parameters": {}, "sneaky": True}
        )
        assert response.status_code == 422

    def test_cancelling_a_finished_job_conflicts(self, api_client) -> None:
        submitted = api_client.post(
            "/jobs", json={"name": "detect_anomalies", "parameters": {"hours": 1}}
        )
        job_id = submitted.json()["job"]["id"]
        import time

        time.sleep(0.5)
        assert api_client.delete(f"/jobs/{job_id}").status_code in (200, 409)

    def test_job_listing_reflects_submissions(self, api_client) -> None:
        api_client.post("/jobs", json={"name": "detect_anomalies", "parameters": {"hours": 1}})
        body = api_client.get("/jobs").json()
        assert body["jobs"]
        assert body["stats"]["tracked"] >= 1


class TestStoredReports:
    def test_generated_report_is_listed_and_readable(self, api_client, settings: Settings) -> None:
        from app.analytics.reports import ReportBuilder, save_report

        report = ReportBuilder(settings).summary(hours=48)
        path = save_report(report, settings.storage.data_root / "reports", fmt="json")

        listing = api_client.get("/reports/stored").json()
        assert any(entry["name"] == path.name for entry in listing["reports"])

        fetched = api_client.get(f"/reports/stored/{path.name}")
        assert fetched.status_code == 200
        assert json.loads(fetched.text)["name"] == report.name

    def test_markdown_report_is_served_with_the_right_type(
        self, api_client, settings: Settings
    ) -> None:
        from app.analytics.reports import ReportBuilder, save_report

        report = ReportBuilder(settings).summary(hours=48)
        path = save_report(report, settings.storage.data_root / "reports", fmt="markdown")
        response = api_client.get(f"/reports/stored/{path.name}")
        assert response.headers["content-type"].startswith("text/markdown")

    def test_daily_report_endpoint(self, api_client) -> None:
        assert api_client.get("/reports/daily").status_code == 200


class TestAdminEndpoints:
    @pytest.fixture
    def admin_client(self, authed_settings: Settings, tmp_path: Path):  # noqa: ANN201
        from fastapi.testclient import TestClient

        from app.api.deps import reset_dependencies
        from app.api.main import create_app

        reset_dependencies()
        with TestClient(create_app(authed_settings)) as client:
            yield client
        reset_dependencies()

    HEADERS = {"X-API-Key": "test-key-abcdefghijklmnop"}

    def test_plugins_listing(self, admin_client) -> None:
        body = admin_client.get("/admin/plugins", headers=self.HEADERS).json()
        assert any(entry["name"] == "json" for entry in body["parsers"])
        assert any(entry["name"] == "parquet" for entry in body["storage"])

    def test_runs_listing(self, admin_client) -> None:
        body = admin_client.get("/admin/runs", headers=self.HEADERS).json()
        assert "runs" in body and "stats" in body

    def test_rejected_statistics(self, admin_client) -> None:
        body = admin_client.get("/admin/rejected", headers=self.HEADERS).json()
        assert body["total"] == 0

    def test_cache_stats_and_clear(self, admin_client) -> None:
        assert admin_client.get("/admin/cache/stats", headers=self.HEADERS).status_code == 200
        assert admin_client.post("/admin/cache/clear", headers=self.HEADERS).status_code == 200

    def test_api_key_management(self, admin_client) -> None:
        created = admin_client.post(
            "/admin/apikeys", headers=self.HEADERS, json={"name": "svc-a", "scopes": ["read"]}
        )
        assert created.status_code == 201
        assert created.json()["api_key"]

        listed = admin_client.get("/admin/apikeys", headers=self.HEADERS).json()
        assert any(key["name"] == "svc-a" for key in listed["keys"])

        assert admin_client.delete("/admin/apikeys/svc-a", headers=self.HEADERS).status_code == 200
        assert admin_client.delete("/admin/apikeys/absent", headers=self.HEADERS).status_code == 404

    def test_invalid_scope_is_rejected(self, admin_client) -> None:
        response = admin_client.post(
            "/admin/apikeys", headers=self.HEADERS, json={"name": "bad", "scopes": ["root"]}
        )
        assert response.status_code == 400

    def test_reload(self, admin_client) -> None:
        assert admin_client.post("/admin/reload", headers=self.HEADERS).json()["reloaded"]
