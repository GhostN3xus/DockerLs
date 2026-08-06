"""CLI-level checks that numeric options are actually validated.

These are deliberately end-to-end through the Typer app: the unit tests for
``validate_threshold``/``validate_workers`` pass even when nothing in
production code ever calls them, which is exactly the regression this file
guards against.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from dockerls.cli.app import app

runner = CliRunner()

# Any use case build attempt means validation let the value through.
_BUILDERS = (
    "dockerls.cli.commands.recommend.build_recommend_use_case",
    "dockerls.cli.commands.advisor.build_recommend_use_case",
    "dockerls.cli.commands.export.build_recommend_use_case",
    "dockerls.cli.commands.search.build_repository",
)


def _invoke(args: list[str]):
    """Run the CLI with every dependency builder poisoned.

    If validation fails to reject a bad value the command proceeds and blows
    up on the poisoned builder instead, so the test can distinguish "rejected
    by the CLI" from "accepted and executed".
    """
    poison = AsyncMock(side_effect=AssertionError("builder reached: value was not rejected"))
    with (
        patch(_BUILDERS[0], poison),
        patch(_BUILDERS[1], poison),
        patch(_BUILDERS[2], poison),
        patch(_BUILDERS[3], poison),
    ):
        return runner.invoke(app, args)


class TestWorkersValidation:
    @pytest.mark.parametrize("value", ["0", "-1", "-5", "51", "1000"])
    def test_out_of_range_workers_rejected(self, value):
        r = _invoke(["recommend", "node", "--workers", value])
        assert r.exit_code != 0
        assert "workers must be between 1 and 50" in r.output
        # A readable CLI error, not a traceback and not a hang.
        assert "Traceback" not in r.output

    @pytest.mark.parametrize("command", ["advisor", "export"])
    def test_other_commands_reject_workers_zero(self, command):
        r = _invoke([command, "node", "--workers", "0"])
        assert r.exit_code != 0
        assert "workers must be between 1 and 50" in r.output


class TestThresholdValidation:
    @pytest.mark.parametrize(
        ("flag", "param"),
        [
            ("--max-critical", "max_critical"),
            ("--max-high", "max_high"),
            ("--max-medium", "max_medium"),
        ],
    )
    def test_negative_thresholds_rejected(self, flag, param):
        r = _invoke(["recommend", "node", flag, "-1"])
        assert r.exit_code != 0
        assert f"{param} must be non-negative" in r.output

    def test_oversized_threshold_rejected(self):
        r = _invoke(["recommend", "node", "--max-medium", "100000"])
        assert r.exit_code != 0
        assert "max_medium exceeds maximum allowed value" in r.output


class TestLimitValidation:
    @pytest.mark.parametrize("value", ["0", "-1"])
    def test_non_positive_limit_rejected(self, value):
        r = _invoke(["recommend", "node", "--limit", value])
        assert r.exit_code != 0
        assert "limit must be at least 1" in r.output

    def test_oversized_limit_rejected(self):
        r = _invoke(["recommend", "node", "--limit", "999999999"])
        assert r.exit_code != 0
        assert "limit exceeds maximum allowed value" in r.output

    def test_search_limit_rejected(self):
        r = _invoke(["search", "node", "--limit", "0"])
        assert r.exit_code != 0
        assert "limit must be at least 1" in r.output


class TestFormatValidation:
    """An invalid --format must error, not silently fall back to the table."""

    @pytest.mark.parametrize("command", ["recommend", "advisor"])
    def test_invalid_format_rejected(self, command):
        r = _invoke([command, "node", "--format", "jsonn"])
        assert r.exit_code != 0
        assert "jsonn" in r.output

    @pytest.mark.parametrize("command", ["recommend", "advisor"])
    @pytest.mark.parametrize("value", ["table", "json"])
    def test_valid_formats_accepted(self, command, value):
        # Reaching the poisoned builder proves the value passed validation.
        r = _invoke([command, "node", "--format", value])
        assert isinstance(r.exception, AssertionError)


class TestUseCaseGuards:
    """The use case itself refuses values that would deadlock it."""

    def test_workers_zero_rejected(self):
        from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase

        with pytest.raises(ValueError, match="workers must be between 1 and 50"):
            RecommendImagesUseCase(
                repository=AsyncMock(),
                scanner=AsyncMock(),
                eol_checker=AsyncMock(),
                workers=0,
            )

    def test_negative_threshold_rejected(self):
        from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase

        with pytest.raises(ValueError, match="max_critical must be non-negative"):
            RecommendImagesUseCase(
                repository=AsyncMock(),
                scanner=AsyncMock(),
                eol_checker=AsyncMock(),
                max_critical=-1,
            )
