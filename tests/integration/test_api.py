"""API integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.config import Settings

pytestmark = pytest.mark.integration


class TestHealth:
    def test_root_advertises_entry_points(self, api_client) -> None:
        body = api_client.get("/").json()
        assert body["health"] == "/health"
        assert body["version"]

    def test_liveness_never_touches_dependencies(self, api_client) -> None:
        assert api_client.get("/health/live").json()["status"] == "alive"

    def test_readiness_reports_components(self, api_client) -> None:
        body = api_client.get("/health/ready").json()
        assert body["status"] == "ready"
        assert body["checks"]["storage"] == "ok"

    def test_health_summary_includes_record_counts(self, api_client) -> None:
        body = api_client.get("/health").json()
        assert body["components"]["storage"]["records"] == 200

    def test_metrics_are_prometheus_formatted(self, api_client) -> None:
        response = api_client.get("/metrics")
        assert response.status_code == 200
        assert "loga_http_requests_total" in response.text

    def test_stats(self, api_client) -> None:
        body = api_client.get("/stats").json()
        assert body["records"] == 200
        assert body["services"] == 4


class TestLogs:
    def test_listing_is_paginated(self, api_client) -> None:
        body = api_client.get("/logs", params={"page_size": 10, "hours": 48}).json()
        assert len(body["items"]) == 10
        assert body["pagination"]["total"] == 200
        assert body["pagination"]["pages"] == 20

    def test_filters_narrow_results(self, api_client) -> None:
        body = api_client.get("/logs", params={"level": "ERROR", "hours": 48}).json()
        assert body["pagination"]["total"] == 50

    def test_sorting(self, api_client) -> None:
        ascending = api_client.get(
            "/logs", params={"sort_order": "asc", "page_size": 1, "hours": 48}
        ).json()
        descending = api_client.get(
            "/logs", params={"sort_order": "desc", "page_size": 1, "hours": 48}
        ).json()
        assert ascending["items"][0]["timestamp"] < descending["items"][0]["timestamp"]

    def test_search_query_language(self, api_client) -> None:
        body = api_client.get(
            "/logs/search", params={"q": "level=ERROR AND status_code>=500", "hours": 48}
        ).json()
        assert body["pagination"]["total"] == 50

    def test_search_explain_shows_the_predicate(self, api_client) -> None:
        body = api_client.get("/logs/search", params={"q": "service=api", "explain": True}).json()
        assert "?" in body["explain"]["predicate"]
        assert body["explain"]["parameters"] == 1

    def test_invalid_query_returns_400(self, api_client) -> None:
        response = api_client.get("/logs/search", params={"q": "nope=1"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "search_syntax_error"

    def test_fetch_by_event_id(self, api_client) -> None:
        listed = api_client.get("/logs", params={"page_size": 1, "hours": 48}).json()
        event_id = listed["items"][0]["event_id"]
        assert api_client.get(f"/logs/{event_id}").json()["event_id"] == event_id

    def test_unknown_event_id_returns_404(self, api_client) -> None:
        assert api_client.get("/logs/0123456789abcdef").status_code == 404

    def test_field_metadata_and_suggestions(self, api_client) -> None:
        assert "service" in api_client.get("/logs/fields").json()["fields"]
        values = api_client.get("/logs/fields/service/values").json()["values"]
        assert "api" in values

    def test_export_streams_ndjson(self, api_client) -> None:
        response = api_client.get("/logs/export/stream", params={"limit": 25, "hours": 48})
        assert response.status_code == 200
        lines = [line for line in response.text.splitlines() if line.strip()]
        assert len(lines) == 25

    def test_page_size_is_clamped(self, api_client) -> None:
        response = api_client.get("/logs", params={"page_size": 99_999})
        assert response.status_code == 422  # above the declared maximum


class TestAnalyticsEndpoints:
    @pytest.mark.parametrize(
        "path",
        [
            "/analytics/overview",
            "/analytics/errors",
            "/analytics/traffic",
            "/analytics/latency",
            "/analytics/status-codes",
            "/analytics/services",
            "/analytics/timeseries",
            "/analytics/anomalies",
            "/analytics/security",
            "/analytics/windows",
        ],
    )
    def test_endpoints_respond(self, api_client, path: str) -> None:
        assert api_client.get(path, params={"hours": 48}).status_code == 200

    def test_overview_numbers(self, api_client) -> None:
        body = api_client.get("/analytics/overview", params={"hours": 48}).json()
        assert body["total_records"] == 200
        assert body["total_errors"] == 50

    def test_unknown_metric_is_rejected(self, api_client) -> None:
        response = api_client.get("/analytics/timeseries", params={"metric": "nope"})
        assert response.status_code == 400

    def test_invalid_window_is_rejected(self, api_client) -> None:
        response = api_client.get("/analytics/errors", params={"window": "3m"})
        assert response.status_code == 422

    def test_responses_are_cached(self, api_client) -> None:
        first = api_client.get("/analytics/overview", params={"hours": 48})
        second = api_client.get("/analytics/overview", params={"hours": 48})
        assert first.json()["total_records"] == second.json()["total_records"]


class TestReportsEndpoints:
    def test_summary_json(self, api_client) -> None:
        body = api_client.get("/reports/summary", params={"hours": 48}).json()
        assert body["overview"]["total_records"] == 200

    def test_summary_markdown(self, api_client) -> None:
        response = api_client.get("/reports/summary", params={"hours": 48, "format": "markdown"})
        assert response.headers["content-type"].startswith("text/markdown")
        assert "# " in response.text

    def test_summary_html(self, api_client) -> None:
        response = api_client.get("/reports/summary", params={"hours": 48, "format": "html"})
        assert "<html>" in response.text

    def test_stored_listing_when_empty(self, api_client) -> None:
        assert api_client.get("/reports/stored").json()["reports"] == []

    def test_unknown_stored_report_returns_404(self, api_client) -> None:
        assert api_client.get("/reports/stored/missing.json").status_code == 404


class TestJobsEndpoints:
    def test_available_jobs(self, api_client) -> None:
        body = api_client.get("/jobs/available").json()
        assert "ingest" in body["jobs"]
        assert "cleanup" in body["admin_only"]

    def test_listing_is_empty_initially(self, api_client) -> None:
        assert api_client.get("/jobs").json()["jobs"] == []

    def test_unknown_job_id_returns_404(self, api_client) -> None:
        assert api_client.get("/jobs/abcdef01").status_code == 404


class TestErrorHandling:
    def test_unknown_route_returns_the_error_envelope(self, api_client) -> None:
        body = api_client.get("/does-not-exist").json()
        assert body["error"]["code"] == "not_found"
        assert "request_id" in body["error"]

    def test_validation_errors_describe_the_field(self, api_client) -> None:
        body = api_client.get("/logs", params={"page": 0}).json()
        assert body["error"]["code"] == "validation_error"
        assert body["error"]["details"]

    def test_every_response_carries_a_request_id(self, api_client) -> None:
        response = api_client.get("/health")
        assert response.headers["X-Request-ID"]

    def test_inbound_request_id_is_honoured(self, api_client) -> None:
        response = api_client.get("/health", headers={"X-Request-ID": "trace-me-123"})
        assert response.headers["X-Request-ID"] == "trace-me-123"


class TestOpenApi:
    def test_schema_is_served_and_documents_the_routes(self, api_client) -> None:
        schema = api_client.get("/openapi.json").json()
        for path in ("/logs", "/logs/search", "/analytics/overview", "/reports/daily"):
            assert path in schema["paths"]

    def test_docs_can_be_disabled(self, settings: Settings, populated_store: Path) -> None:
        from fastapi.testclient import TestClient

        from app.api.deps import reset_dependencies
        from app.api.main import create_app

        reset_dependencies()
        hardened = settings.model_copy(
            update={"api": settings.api.model_copy(update={"docs_enabled": False})}
        )
        with TestClient(create_app(hardened)) as client:
            assert client.get("/docs").status_code == 404
            assert client.get("/openapi.json").status_code == 404
        reset_dependencies()


class TestDashboard:
    def test_dashboard_is_served(self, api_client) -> None:
        response = api_client.get("/dashboard")
        assert response.status_code == 200
        assert "<title>Log Analytics</title>" in response.text

    def test_dashboard_has_no_external_dependencies(self, api_client) -> None:
        """A CDN reference would be blocked by the CSP and break the page."""
        html = api_client.get("/dashboard").text
        for marker in ("https://cdn", "http://cdn", "unpkg.com", "jsdelivr"):
            assert marker not in html

    def test_dashboard_page_carries_no_inline_code(self, api_client) -> None:
        """No inline <script>/<style>, so the CSP can drop 'unsafe-inline'."""
        html = api_client.get("/dashboard").text
        assert "<style" not in html
        assert 'style="' not in html
        assert "<script>" not in html

    def test_dashboard_assets_are_served_from_the_same_origin(self, api_client) -> None:
        html = api_client.get("/dashboard").text
        assert '<link rel="stylesheet" href="/dashboard/dashboard.css">' in html
        assert '<script src="/dashboard/dashboard.js" defer></script>' in html

        css = api_client.get("/dashboard/dashboard.css")
        assert css.status_code == 200
        assert css.headers["content-type"].startswith("text/css")
        assert "--accent" in css.text

        script = api_client.get("/dashboard/dashboard.js")
        assert script.status_code == 200
        assert "javascript" in script.headers["content-type"]
        assert "textContent" in script.text
