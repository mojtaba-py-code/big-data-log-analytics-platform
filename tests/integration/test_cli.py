"""CLI integration tests.

Exercised through Typer's runner so the tests cover argument parsing, exit
codes and output shape — the parts a user actually touches.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from app.cli.main import EXIT_OK, EXIT_USAGE, app

pytestmark = pytest.mark.integration

runner = CliRunner()


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the CLI at an isolated data root via environment variables."""
    root = tmp_path / "data"
    (root / "raw").mkdir(parents=True)
    monkeypatch.setenv("LOGA_STORAGE__DATA_ROOT", str(root))
    monkeypatch.setenv("LOGA_INGESTION__ALLOWED_ROOTS", json.dumps([str(tmp_path)]))
    monkeypatch.setenv("LOGA_DATABASE__SQLITE_PATH", str(tmp_path / "meta.db"))
    monkeypatch.setenv("LOGA_OBSERVABILITY__LEVEL", "ERROR")
    monkeypatch.setenv("LOGA_ENVIRONMENT", "test")
    return root


class TestBasics:
    def test_version(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == EXIT_OK
        assert "loganalytics" in result.stdout

    def test_help_lists_the_commands(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == EXIT_OK
        for command in ("ingest", "analyze", "search", "report", "stats", "generate"):
            assert command in result.stdout

    def test_bare_invocation_shows_help(self) -> None:
        # No command is a usage error (exit 2), and the help text is printed.
        result = runner.invoke(app, [])
        assert result.exit_code == EXIT_USAGE
        assert "Usage" in result.stdout

    def test_unknown_command_is_a_usage_error(self) -> None:
        assert runner.invoke(app, ["nonsense"]).exit_code != EXIT_OK


class TestGenerateAndIngest:
    def test_generate_creates_a_dataset(self, cli_env: Path) -> None:
        target = cli_env / "raw" / "demo.log"
        result = runner.invoke(app, ["generate", str(target), "-n", "500"])
        assert result.exit_code == EXIT_OK
        assert target.exists()
        assert len(target.read_text(encoding="utf-8").splitlines()) >= 500

    @pytest.mark.parametrize("fmt", ["json", "access", "plaintext", "csv"])
    def test_generate_every_format(self, cli_env: Path, fmt: str) -> None:
        target = cli_env / "raw" / f"demo-{fmt}.log"
        assert runner.invoke(app, ["generate", str(target), "-n", "50", "-f", fmt]).exit_code == 0

    def test_ingest_then_stats(self, cli_env: Path) -> None:
        target = cli_env / "raw" / "demo.log"
        runner.invoke(app, ["generate", str(target), "-n", "500", "-f", "json"])
        ingest = runner.invoke(app, ["ingest", str(target), "--json"])
        assert ingest.exit_code in (EXIT_OK, 3)
        stats = runner.invoke(app, ["stats", "--json"])
        assert stats.exit_code == EXIT_OK
        assert '"records"' in stats.stdout

    def test_dry_run_writes_nothing(self, cli_env: Path) -> None:
        target = cli_env / "raw" / "dry.log"
        runner.invoke(app, ["generate", str(target), "-n", "100", "-f", "json"])
        runner.invoke(app, ["ingest", str(target), "--dry-run"])
        assert not list((cli_env / "processed").rglob("*.parquet"))

    def test_ingesting_a_missing_file_fails_cleanly(self, cli_env: Path) -> None:
        result = runner.invoke(app, ["ingest", str(cli_env / "raw" / "absent.log")])
        assert result.exit_code != EXIT_OK
        assert "Traceback" not in result.stdout


class TestAnalysis:
    @pytest.fixture(autouse=True)
    def _ingested(self, cli_env: Path) -> None:
        target = cli_env / "raw" / "data.log"
        runner.invoke(app, ["generate", str(target), "-n", "2000", "-f", "json"])
        runner.invoke(app, ["ingest", str(target)])

    def test_analyze_json_output_is_parseable(self) -> None:
        result = runner.invoke(app, ["analyze", "--hours", "48", "--json"])
        assert result.exit_code == EXIT_OK
        payload = json.loads(result.stdout)
        assert payload["total_records"] > 0

    def test_analyze_table_output(self) -> None:
        result = runner.invoke(app, ["analyze", "--hours", "48"])
        assert result.exit_code == EXIT_OK
        assert "total_records" in result.stdout

    def test_search_finds_records(self) -> None:
        result = runner.invoke(app, ["search", "level=ERROR", "--hours", "48", "-n", "5"])
        assert result.exit_code == EXIT_OK

    def test_search_rejects_a_bad_query(self) -> None:
        result = runner.invoke(app, ["search", "nope=1", "--hours", "48"])
        assert result.exit_code == EXIT_USAGE

    def test_report_markdown(self) -> None:
        result = runner.invoke(app, ["report", "--hours", "48", "--format", "markdown"])
        assert result.exit_code == EXIT_OK
        assert "# " in result.stdout

    def test_report_to_file(self, tmp_path: Path) -> None:
        output = tmp_path / "reports" / "out.md"
        result = runner.invoke(
            app, ["report", "--hours", "48", "--format", "markdown", "-o", str(output)]
        )
        assert result.exit_code == EXIT_OK
        assert list((tmp_path / "reports").glob("*.md"))

    def test_dlq_stats(self) -> None:
        assert runner.invoke(app, ["dlq", "stats", "--json"]).exit_code == EXIT_OK


class TestConfigAndKeys:
    def test_config_show_redacts_secrets(self, cli_env: Path) -> None:
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == EXIT_OK
        assert "data_root" in result.stdout

    def test_config_validate(self, cli_env: Path) -> None:
        assert runner.invoke(app, ["config", "validate"]).exit_code == EXIT_OK

    def test_config_validate_rejects_unsafe_production(self, cli_env: Path) -> None:
        result = runner.invoke(app, ["config", "validate", "--environment", "production"])
        assert result.exit_code == EXIT_USAGE

    def test_api_key_lifecycle(self, cli_env: Path) -> None:
        created = runner.invoke(app, ["apikey", "create", "ci", "--scopes", "read,write"])
        assert created.exit_code == EXIT_OK
        assert runner.invoke(app, ["apikey", "list"]).exit_code == EXIT_OK
        assert runner.invoke(app, ["apikey", "revoke", "ci"]).exit_code == EXIT_OK

    def test_invalid_scope_is_rejected(self, cli_env: Path) -> None:
        result = runner.invoke(app, ["apikey", "create", "bad", "--scopes", "root"])
        assert result.exit_code == EXIT_USAGE


class TestPlugins:
    def test_plugins_lists_registered_components(self) -> None:
        result = runner.invoke(app, ["plugins", "--json"])
        assert result.exit_code == EXIT_OK
        payload = json.loads(result.stdout)
        assert any(entry["name"] == "json" for entry in payload["parsers"])
        assert "ingest" in payload["jobs"]

    def test_json_output_is_never_colourised(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """``--json`` must stay parseable even when colour is forced on.

        Many CI images export FORCE_COLOR=1.  Rich would then syntax-highlight
        the JSON, and ANSI escapes in stdout break ``--json | jq``.
        """
        monkeypatch.setenv("FORCE_COLOR", "1")
        result = runner.invoke(app, ["plugins", "--json"])
        assert result.exit_code == EXIT_OK
        assert "\x1b[" not in result.stdout
        json.loads(result.stdout)


class TestJobs:
    def test_run_a_registered_job(self, cli_env: Path) -> None:
        result = runner.invoke(
            app,
            ["job", "run", "generate_data", "--params", '{"count": 100}', "--json"],
        )
        assert result.exit_code == EXIT_OK
        assert '"records"' in result.stdout

    def test_unknown_job_is_a_usage_error(self, cli_env: Path) -> None:
        assert runner.invoke(app, ["job", "run", "nope"]).exit_code == EXIT_USAGE

    def test_malformed_params_are_rejected(self, cli_env: Path) -> None:
        result = runner.invoke(app, ["job", "run", "generate_data", "--params", "{bad"])
        assert result.exit_code == EXIT_USAGE
