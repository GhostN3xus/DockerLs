"""The options every measuring command shares, through the real Typer app.

Invalid values must exit 1 (a usage error) -- never 2, which is a verdict --
and must be rejected before any use case is built. Valid ones must reach the
use case, and a partial run must not look like a complete one.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis
from dockerls.cli.app import app
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.exit_codes import EXIT_ERROR, EXIT_PARTIAL_RESULT, EXIT_TIME_BUDGET_EXHAUSTED

runner = CliRunner()

_BUILDERS = (
    "dockerls.cli.commands.recommend.build_recommend_use_case",
    "dockerls.cli.commands.alternatives.build_recommend_use_case",
    "dockerls.cli.commands.advisor.build_recommend_use_case",
    "dockerls.cli.commands.analyze.build_analyze_use_case",
    "dockerls.cli.commands.compare.build_analyze_use_case",
)


def _poisoned(args: list[str]):
    boom = AsyncMock(side_effect=AssertionError("builder reached: the option was not rejected"))
    patches = [patch(name, boom) for name in _BUILDERS if _exists(name)]
    for p in patches:
        p.start()
    try:
        return runner.invoke(app, args)
    finally:
        for p in patches:
            p.stop()


def _exists(dotted: str) -> bool:
    module, _, attr = dotted.rpartition(".")
    try:
        return hasattr(__import__(module, fromlist=[attr]), attr)
    except ImportError:
        return False


COMMANDS = [
    ["recommend", "node"],
    ["analyze", "node:22"],
    ["compare", "node:22", "node:20"],
]


@pytest.mark.parametrize("command", COMMANDS, ids=lambda c: c[0])
class TestInvalidSharedOptions:
    @pytest.mark.parametrize("value", ["windows", "linux", "linux/", "linux/amd64/v9/x", "a b/c"])
    def test_a_malformed_platform_is_a_usage_error(self, command, value):
        outcome = _poisoned([*command, "--platform", value])
        assert outcome.exit_code == EXIT_ERROR, outcome.output

    @pytest.mark.parametrize("value", ["0", "-5", "nan", "inf", "999999999"])
    def test_a_nonsense_budget_is_a_usage_error(self, command, value):
        outcome = _poisoned([*command, "--time-budget", value])
        assert outcome.exit_code == EXIT_ERROR, outcome.output

    def test_a_non_numeric_budget_never_exits_with_a_verdict_code(self, command):
        outcome = _poisoned([*command, "--time-budget", "soon"])
        assert outcome.exit_code != 2


def _analysis(tag="22") -> ImageAnalysis:
    image = DockerImage(name="node", tag=tag)
    return ImageAnalysis(
        image=image,
        scan=ScanResult(
            image_reference=image.full_reference, scan_timestamp="2026-01-01T00:00:00Z"
        ),
        security_score=95.0,
        tier="A",
        remediation_score=100,
    )


def _recommend(result: AnalysisResult, *args: str):
    uc = AsyncMock()
    uc.execute = AsyncMock(return_value=result)
    with patch(
        "dockerls.cli.commands.recommend.build_recommend_use_case", AsyncMock(return_value=uc)
    ):
        outcome = runner.invoke(app, ["recommend", "node", "--no-progress", *args])
    return outcome, uc


def _result(completeness: str, *, with_image: bool = True, **extra) -> AnalysisResult:
    return AnalysisResult(
        query="node",
        total_tags_scanned=1,
        total_tags_analyzed=1 if with_image else 0,
        baseline_met=True,
        recommendations=[_analysis()] if with_image else [],
        completeness=completeness,
        **extra,
    )


def test_an_unknown_profile_is_a_usage_error():
    outcome = _poisoned(["recommend", "node", "--profile", "turbo"])
    assert outcome.exit_code == EXIT_ERROR, outcome.output


class TestExitCodesWithABudget:
    def test_a_partial_run_is_never_exit_zero(self):
        outcome, _ = _recommend(_result("PARTIAL"), "--time-budget", "30")
        assert outcome.exit_code == EXIT_PARTIAL_RESULT, outcome.output

    def test_a_run_with_nothing_measured_has_its_own_code(self):
        outcome, _ = _recommend(_result("NO_RESULT", with_image=False), "--time-budget", "30")
        assert outcome.exit_code == EXIT_TIME_BUDGET_EXHAUSTED, outcome.output

    def test_a_complete_run_keeps_the_code_it_always_had(self):
        outcome, _ = _recommend(_result("COMPLETE"), "--time-budget", "30")
        assert outcome.exit_code == 0, outcome.output

    def test_without_a_budget_nothing_about_the_exit_code_changes(self):
        outcome, _ = _recommend(_result("COMPLETE"))
        assert outcome.exit_code == 0, outcome.output


class TestStructuredStdout:
    def test_summary_format_is_one_clean_json_document(self):
        outcome, _ = _recommend(_result("COMPLETE"), "--format", "summary")
        assert outcome.exit_code == 0, outcome.output
        document = json.loads(outcome.stdout)
        assert document["schema"].startswith("dockerls.ci-summary/")
        assert "\x1b[" not in outcome.stdout

    def test_summary_of_a_partial_run_says_so(self):
        outcome, _ = _recommend(_result("PARTIAL"), "--format", "summary", "--time-budget", "30")
        document = json.loads(outcome.stdout)
        assert document["completeness"] == "PARTIAL"
        assert document["status"] in {"INCOMPLETE", "PASS_WITH_PENDING_CHECKS"}
        assert outcome.exit_code == EXIT_PARTIAL_RESULT
