"""Unit tests for the synthetic generator's determinism guarantees."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.synthetic.generator import GeneratorConfig, LogGenerator

pytestmark = pytest.mark.unit

START = datetime(2026, 1, 1, tzinfo=UTC)


def _records(**overrides: object) -> list[dict[str, object]]:
    config = GeneratorConfig(start=START, count=500, **overrides)  # type: ignore[arg-type]
    return list(LogGenerator(config).records())


class TestDeterminism:
    def test_same_seed_gives_the_same_dataset(self) -> None:
        assert _records() == _records()

    def test_a_different_seed_gives_a_different_dataset(self) -> None:
        assert _records() != _records(seed=7)

    def test_forced_credentials_leave_every_other_record_alone(self) -> None:
        """The docstring on `_credential_positions` promises exactly this.

        Guaranteeing credential-bearing records must not shift the PRNG
        stream, or a benchmark run with the flag would not be comparable to
        one without it.
        """
        baseline = _records()
        with_credentials = _records(credential_records=4)

        differing = [
            index
            for index, (before, after) in enumerate(zip(baseline, with_credentials, strict=True))
            if before != after
        ]
        forced = sorted(
            LogGenerator(
                GeneratorConfig(start=START, count=500, credential_records=4)
            )._credential_positions()
        )
        assert differing == forced
