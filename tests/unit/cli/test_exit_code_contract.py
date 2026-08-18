"""What every command's exit code means, checked command by command.

A pipeline can only branch on the number, so the number is the API. The
contract:

    0  the command ran and nothing violated a policy
    1  the command could not run, or `--fail-on` was violated -- nothing
       usable was measured, so the result says nothing about security
    2  the command ran and the result violates a policy

`recommend` extends it with two codes of its own (2 = below baseline but
alternatives exist, 3 = nothing usable found), because it chooses between
candidates rather than judging one artefact the user handed it.

The rule these tests exist to keep: a technical failure must never be
reported with a code that reads as a security verdict, and vice versa.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from dockerls.application.dto.analysis import AnalysisResult
from dockerls.cli.app import app
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY

runner = CliRunner()


def _use_case(result: AnalysisResult):
    async def build(**kwargs):
        uc = AsyncMock()
        uc.execute = AsyncMock(return_value=result)
        return uc

    return build


def _empty(query: str = "node") -> AnalysisResult:
    return AnalysisResult(query=query, total_tags_scanned=0, baseline_met=False)


class TestTheContractIsExhaustive:
    def test_the_three_codes_are_the_documented_ones(self):
        assert (EXIT_OK, EXIT_ERROR, EXIT_POLICY) == (0, 1, 2)


class TestUsageErrorsAreOperationalNotPolicy:
    """A typo in a flag is code 1. It must never be 2: `recommend` publishes
    2 as "below baseline, alternatives found", so a CI gate keying on the
    exit code would read a mistyped flag as a security verdict."""

    @pytest.mark.parametrize("command", ["recommend", "advisor"])
    def test_unknown_format_exits_one(self, command):
        result = runner.invoke(app, [command, "node", "--format", "jsonn"])
        assert result.exit_code == EXIT_ERROR
        assert "--format" in result.stdout

    @pytest.mark.parametrize(
        ("args", "expected_text"),
        [
            (["recommend", "node", "--workers", "-1"], "workers must be between"),
            (["recommend", "node", "--limit", "0"], "limit must be at least 1"),
            (["recommend", "node", "--max-critical", "-1"], "must be non-negative"),
            (["search", "node", "--limit", "0"], "limit must be at least 1"),
        ],
    )
    def test_out_of_range_options_are_rejected_before_anything_runs(self, args, expected_text):
        poison = AsyncMock(side_effect=AssertionError("should not have been reached"))
        with (
            patch("dockerls.cli.commands.recommend.build_recommend_use_case", poison),
            patch("dockerls.cli.commands.search.build_search_use_case", poison),
        ):
            result = runner.invoke(app, args)
        assert result.exit_code != EXIT_OK
        assert expected_text in result.output
        assert "Traceback" not in result.output


class TestRecommendCodes:
    def test_nothing_scanned_is_an_error_not_a_verdict(self):
        """Zero scanned tags means the run failed, not that the image is
        clean. Reporting 3 ("nothing usable found") would be a verdict; 1 is
        the truth."""
        with patch("dockerls.cli.commands.recommend.build_recommend_use_case", _use_case(_empty())):
            result = runner.invoke(app, ["recommend", "node", "--no-progress"])
        assert result.exit_code == EXIT_ERROR

    def test_an_unscannable_run_is_an_error_not_a_verdict(self):
        """Code 3 is published as "nothing usable was found" -- a statement
        about the images, which a gate may act on. With no scanner
        installed, nothing was measured at all. Reporting that as 3 is the
        exact substitution this tool must never make."""
        from dockerls.application.dto.analysis import UnverifiedImage

        result = AnalysisResult(
            query="node",
            total_tags_scanned=4,
            total_tags_analyzed=0,
            baseline_met=False,
            unverified=[
                UnverifiedImage(
                    image_reference=f"node:tag{i}",
                    status="ERROR",
                    reason="'trivy' was not found on PATH",
                    kind="SCANNER_MISSING",
                )
                for i in range(4)
            ],
        )
        with patch("dockerls.cli.commands.recommend.build_recommend_use_case", _use_case(result)):
            run = runner.invoke(app, ["recommend", "node", "--no-progress"])

        assert run.exit_code == EXIT_ERROR
        assert "No image could be scanned" in run.stdout
        assert "SCANNER_MISSING" in run.stdout
        assert "Suggested action" in run.stdout
        assert "Install Trivy or Grype" in run.stdout
        assert "not a security verdict" in run.stdout

    def test_scanned_but_nothing_good_enough_still_exits_three(self):
        """The other side of the same coin: tags that *were* measured and
        rejected are a verdict, and must keep code 3."""
        from dockerls.application.dto.analysis import UnverifiedImage

        result = AnalysisResult(
            query="node",
            total_tags_scanned=4,
            total_tags_analyzed=3,
            baseline_met=False,
            unverified=[
                UnverifiedImage(
                    image_reference="node:bad", status="ERROR", reason="x", kind="TIMEOUT"
                )
            ],
        )
        with patch("dockerls.cli.commands.recommend.build_recommend_use_case", _use_case(result)):
            run = runner.invoke(app, ["recommend", "node", "--no-progress"])

        assert run.exit_code == 3
        assert "No suitable images found" in run.stdout

    def test_a_configuration_error_exits_one(self, monkeypatch):
        monkeypatch.setenv("DOCKERLS_MAX_CRITICAL", "-5")
        from dockerls.cli import dependencies

        dependencies._settings.cache_clear()
        try:
            result = runner.invoke(app, ["recommend", "node", "--no-progress"])
        finally:
            dependencies._settings.cache_clear()
        assert result.exit_code == EXIT_ERROR
        assert "Invalid configuration" in result.stdout


class TestAdvisorCodes:
    def test_nothing_to_advise_on_exits_one(self):
        with patch("dockerls.cli.commands.advisor.build_recommend_use_case", _use_case(_empty())):
            result = runner.invoke(app, ["advisor", "node"])
        assert result.exit_code == EXIT_ERROR


class TestSearchCodes:
    def test_no_tags_found_exits_one(self):
        async def build():
            uc = AsyncMock()
            uc.execute = AsyncMock(return_value=[])
            return uc

        with patch("dockerls.cli.commands.search.build_search_use_case", build):
            result = runner.invoke(app, ["search", "nope"])
        assert result.exit_code == EXIT_ERROR

    def test_a_malformed_reference_exits_one_without_a_traceback(self):
        result = runner.invoke(app, ["search", "bad name!"])
        assert result.exit_code == EXIT_ERROR
        assert "Invalid image reference" in result.stdout


class TestExportCodes:
    def test_an_unknown_format_exits_one(self):
        with patch("dockerls.cli.commands.export.build_recommend_use_case", _use_case(_empty())):
            result = runner.invoke(app, ["export", "node", "--format", "nope"])
        assert result.exit_code == EXIT_ERROR


class TestSbomCodes:
    def test_an_unknown_format_exits_one(self):
        result = runner.invoke(app, ["sbom", "node:22", "--format", "nope"])
        assert result.exit_code == EXIT_ERROR

    def test_a_missing_scanner_exits_one(self):
        scanner = AsyncMock()
        scanner.is_available = AsyncMock(return_value=False)
        with patch("dockerls.cli.commands.sbom.TrivyScanner", return_value=scanner):
            result = runner.invoke(app, ["sbom", "node:22"])
        assert result.exit_code == EXIT_ERROR


class TestDoctorGates:
    """`doctor` is what a pipeline runs before a scan job. It printed
    "Some components are missing" and exited 0 anyway, so a runner with no
    scanner at all passed the check and failed later, inside the scan,
    where the cause is much harder to see."""

    def test_no_scanner_at_all_exits_one(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == EXIT_ERROR
        assert "cannot measure anything" in result.stdout

    def test_the_failure_names_a_cause_and_an_action(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        result = runner.invoke(app, ["doctor"])
        assert "Cause" in result.stdout
        assert "Suggested action" in result.stdout
        assert "aquasecurity.github.io/trivy" in result.stdout

    def test_both_scanners_present_exits_zero(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == EXIT_OK

    @pytest.mark.parametrize("installed", ["trivy", "grype"])
    def test_one_scanner_is_enough_to_pass(self, monkeypatch, installed):
        """`ScannerFactory` runs on Grype alone, so a Grype-only machine is
        usable. Failing it would be a false alarm."""
        monkeypatch.setattr(
            "shutil.which", lambda name: f"/usr/bin/{name}" if name == installed else None
        )
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == EXIT_OK
        assert "Only one scanner" in result.stdout


class TestVersionAlwaysSucceeds:
    def test_version_exits_zero(self):
        result = runner.invoke(app, ["version"])
        assert result.exit_code == EXIT_OK


class TestNoCommandUsesALiteralExitCode:
    """The contract module says the codes are defined once. Literals drifting
    back into commands is how 1 and 2 got mixed up in the first place."""

    def test_commands_import_the_contract_instead(self):
        from pathlib import Path

        offenders = []
        for path in Path("dockerls/cli/commands").glob("*.py"):
            source = path.read_text(encoding="utf-8")
            for literal in ("typer.Exit(1)", "typer.Exit(2)", "typer.Exit(0)"):
                if literal in source:
                    offenders.append(f"{path}: {literal}")
        assert not offenders, f"literal exit codes: {offenders}"
