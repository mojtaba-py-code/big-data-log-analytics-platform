"""Ingestion source tests: files, directories, databases and HTTP APIs."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from app.core.config import Settings
from app.core.exceptions import ConfigurationError, IngestionError
from app.ingestion import (
    ApiSource,
    CsvFileSource,
    DatabaseSource,
    DirectorySource,
    FileSource,
    JsonArrayFileSource,
    build_source,
    open_file_source,
)

pytestmark = pytest.mark.integration


class TestFileSource:
    def test_reads_lines_with_numbers(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        path.write_text("first\nsecond\nthird\n", encoding="utf-8")
        records = list(FileSource(path).read())
        assert [record.payload for record in records] == ["first", "second", "third"]
        assert [record.line_number for record in records] == [1, 2, 3]

    def test_blank_lines_are_skipped_and_counted(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        path.write_text("one\n\n\ntwo\n", encoding="utf-8")
        source = FileSource(path)
        assert len(list(source.read())) == 2
        assert source.stats.skipped_empty == 2

    def test_gzip_is_transparent(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log.gz"
        with gzip.open(path, "wt", encoding="utf-8") as stream:
            stream.write("alpha\nbeta\n")
        assert len(list(FileSource(path).read())) == 2

    def test_service_name_is_derived_from_the_filename(self, tmp_path: Path) -> None:
        path = tmp_path / "payment-api.log"
        path.write_text("x\n", encoding="utf-8")
        assert FileSource(path).suggested_service() == "payment-api"

    def test_sample_reads_only_the_head(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        path.write_text("\n".join(f"line{i}" for i in range(1_000)), encoding="utf-8")
        assert len(FileSource(path).sample(5)) == 5

    def test_estimated_size(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        path.write_text("hello\n", encoding="utf-8")
        assert FileSource(path).estimated_bytes() == path.stat().st_size

    def test_directory_target_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(IngestionError):
            FileSource(tmp_path)

    def test_invalid_encoding_is_replaced_not_fatal(self, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        path.write_bytes(b"valid line\n\xff\xfe invalid bytes\n")
        assert len(list(FileSource(path).read())) == 2

    def test_allowed_roots_are_enforced(self, tmp_path: Path) -> None:
        from app.core.exceptions import PathTraversalError

        inside = tmp_path / "allowed"
        inside.mkdir()
        outside = tmp_path / "outside.log"
        outside.write_text("x", encoding="utf-8")
        with pytest.raises(PathTraversalError):
            FileSource(outside, allowed_roots=[inside])


class TestCsvSource:
    def test_header_becomes_field_names(self, tmp_path: Path) -> None:
        path = tmp_path / "a.csv"
        path.write_text("ts,level,message\n2026-08-07,INFO,hello\n", encoding="utf-8")
        records = list(CsvFileSource(path).read())
        assert records[0].payload == {"ts": "2026-08-07", "level": "INFO", "message": "hello"}

    def test_semicolon_dialect_is_sniffed(self, tmp_path: Path) -> None:
        path = tmp_path / "a.csv"
        path.write_text("ts;level;message\n2026-08-07;INFO;hi\n", encoding="utf-8")
        assert list(CsvFileSource(path).read())[0].payload["level"] == "INFO"

    def test_forced_delimiter(self, tmp_path: Path) -> None:
        path = tmp_path / "a.tsv"
        path.write_text("ts\tlevel\n2026-08-07\tINFO\n", encoding="utf-8")
        assert list(CsvFileSource(path, delimiter="\t").read())[0].payload["level"] == "INFO"

    def test_extra_columns_are_preserved(self, tmp_path: Path) -> None:
        path = tmp_path / "a.csv"
        path.write_text("a,b\n1,2,3\n", encoding="utf-8")
        assert list(CsvFileSource(path).read())[0].payload["_extra"] == ["3"]

    def test_missing_header_is_an_error(self, tmp_path: Path) -> None:
        path = tmp_path / "a.csv"
        path.write_text("", encoding="utf-8")
        assert list(CsvFileSource(path).read()) == []


class TestJsonArraySource:
    def test_reads_an_array_of_objects(self, tmp_path: Path) -> None:
        path = tmp_path / "a.json"
        path.write_text(json.dumps([{"message": "a"}, {"message": "b"}]), encoding="utf-8")
        assert len(list(JsonArrayFileSource(path).read())) == 2

    def test_single_object_is_accepted(self, tmp_path: Path) -> None:
        path = tmp_path / "a.json"
        path.write_text(json.dumps({"message": "a"}), encoding="utf-8")
        assert len(list(JsonArrayFileSource(path).read())) == 1

    def test_oversized_file_is_refused_with_advice(self, tmp_path: Path) -> None:
        path = tmp_path / "a.json"
        path.write_text(json.dumps([{"m": "x" * 100} for _ in range(100)]), encoding="utf-8")
        with pytest.raises(IngestionError, match="JSONL"):
            list(JsonArrayFileSource(path, inline_limit=100).read())

    def test_invalid_json_is_an_error(self, tmp_path: Path) -> None:
        path = tmp_path / "a.json"
        path.write_text("{oops", encoding="utf-8")
        with pytest.raises(IngestionError):
            list(JsonArrayFileSource(path).read())


class TestDirectorySource:
    def test_reads_every_matching_file_in_order(self, tmp_path: Path) -> None:
        directory = tmp_path / "logs"
        directory.mkdir()
        for index in range(3):
            (directory / f"{index}.log").write_text(f"line{index}\n", encoding="utf-8")
        (directory / "ignored.bin").write_text("nope", encoding="utf-8")
        records = list(DirectorySource(directory).read())
        assert [record.payload for record in records] == ["line0", "line1", "line2"]

    def test_recurses_into_subdirectories(self, tmp_path: Path) -> None:
        nested = tmp_path / "logs" / "2026" / "08"
        nested.mkdir(parents=True)
        (nested / "a.log").write_text("deep\n", encoding="utf-8")
        assert len(list(DirectorySource(tmp_path / "logs").read())) == 1

    def test_missing_directory_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises((IngestionError, FileNotFoundError)):
            DirectorySource(tmp_path / "absent")

    def test_estimates_total_size(self, tmp_path: Path) -> None:
        directory = tmp_path / "logs"
        directory.mkdir()
        (directory / "a.log").write_text("hello\n", encoding="utf-8")
        assert DirectorySource(directory).estimated_bytes() > 0


class TestSourceFactory:
    def test_file_dispatch(self, settings: Settings, tmp_path: Path) -> None:
        path = tmp_path / "a.log"
        path.write_text("x\n", encoding="utf-8")
        assert isinstance(build_source(path, settings), FileSource)

    def test_csv_dispatch(self, settings: Settings, tmp_path: Path) -> None:
        path = tmp_path / "a.csv"
        path.write_text("a,b\n1,2\n", encoding="utf-8")
        assert isinstance(build_source(path, settings), CsvFileSource)

    def test_directory_dispatch(self, settings: Settings, tmp_path: Path) -> None:
        directory = tmp_path / "logs"
        directory.mkdir()
        assert isinstance(build_source(directory, settings), DirectorySource)

    def test_http_dispatch_is_ssrf_checked(self, settings: Settings) -> None:
        from app.core.exceptions import SecurityError

        with pytest.raises(SecurityError):
            build_source("http://127.0.0.1/logs", settings)

    def test_gzipped_extension_is_seen_through(self, tmp_path: Path) -> None:
        path = tmp_path / "access.log.gz"
        with gzip.open(path, "wt", encoding="utf-8") as stream:
            stream.write("x\n")
        assert isinstance(open_file_source(path), FileSource)


class TestDatabaseSource:
    def test_requires_a_table_or_query(self) -> None:
        with pytest.raises(ConfigurationError):
            DatabaseSource("sqlite:///:memory:")

    def test_rejects_both_table_and_query(self) -> None:
        with pytest.raises(ConfigurationError):
            DatabaseSource("sqlite:///:memory:", table="logs", query="SELECT 1")

    def test_describe_never_leaks_the_dsn(self) -> None:
        source = DatabaseSource("postgresql://user:secret@host/db", table="logs")
        assert "secret" not in source.describe()

    def test_reads_rows_from_sqlite(self, tmp_path: Path) -> None:
        import sqlite3

        database = tmp_path / "logs.db"
        connection = sqlite3.connect(database)
        connection.execute("CREATE TABLE logs (ts TEXT, level TEXT, message TEXT, status INTEGER)")
        connection.executemany(
            "INSERT INTO logs VALUES (?, ?, ?, ?)",
            [
                ("2026-08-07T12:00:00Z", "INFO", "started", 200),
                ("2026-08-07T12:00:01Z", "ERROR", "failed", 500),
            ],
        )
        connection.commit()
        connection.close()

        source = DatabaseSource(f"sqlite:///{database.as_posix()}", table="logs")
        records = list(source.read())
        source.close()
        assert len(records) == 2
        assert records[0].payload["level"] == "INFO"

    def test_time_filters_are_bound_parameters(self) -> None:
        from datetime import UTC, datetime

        source = DatabaseSource(
            "sqlite:///:memory:",
            table="logs",
            timestamp_column="ts",
            since=datetime(2026, 8, 1, tzinfo=UTC),
            until=datetime(2026, 8, 2, tzinfo=UTC),
            limit=100,
        )
        sql, params = source._build_query()
        assert sql.count("?") == 0  # SQLAlchemy named style
        assert ":since" in sql and ":until" in sql and ":row_limit" in sql
        assert params["row_limit"] == 100

    def test_column_projection_is_validated(self) -> None:
        source = DatabaseSource("sqlite:///:memory:", table="logs", columns=["ts", "level"])
        sql, _ = source._build_query()
        assert '"ts", "level"' in sql

    def test_invalid_column_is_rejected(self) -> None:
        source = DatabaseSource("sqlite:///:memory:", table="logs", columns=["ts; DROP"])
        with pytest.raises(ConfigurationError):
            source._build_query()


class TestApiSource:
    def test_rejects_private_targets_at_construction(self) -> None:
        from app.core.exceptions import SecurityError

        with pytest.raises(SecurityError):
            ApiSource("http://169.254.169.254/latest/meta-data/")

    def test_allows_private_targets_when_permitted(self) -> None:
        source = ApiSource("http://127.0.0.1:9999/logs", allow_private=True)
        assert source.describe() == "http://127.0.0.1:9999/logs"

    def test_reads_a_paginated_endpoint(self, monkeypatch: pytest.MonkeyPatch) -> None:
        httpx = pytest.importorskip("httpx")

        pages = {
            1: {"items": [{"message": "a"}, {"message": "b"}], "next": "cursor-2"},
            2: {"items": [{"message": "c"}], "next": None},
        }
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(200, json=pages[calls["n"]])

        transport = httpx.MockTransport(handler)
        original_client = httpx.Client

        def patched_client(*args: object, **kwargs: object) -> httpx.Client:
            kwargs.pop("verify", None)
            return original_client(*args, transport=transport, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(httpx, "Client", patched_client)

        source = ApiSource(
            "http://127.0.0.1:9999/logs",
            allow_private=True,
            records_path="items",
            next_cursor_path="next",
        )
        records = list(source.read())
        assert [record.payload["message"] for record in records] == ["a", "b", "c"]
