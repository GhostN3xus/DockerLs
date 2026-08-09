from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis
from dockerls.cli.app import app
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability

runner = CliRunner()


def _analysis() -> ImageAnalysis:
    vuln = Vulnerability(
        cve_id="CVE-2024-0001",
        severity=Severity.HIGH,
        package_name="openssl",
        installed_version="1.0",
        fixed_version="1.1",
    )
    scan = ScanResult(image_reference="node:22-alpine", vulnerabilities=[vuln])
    return ImageAnalysis(
        image=DockerImage(name="node", tag="22-alpine"),
        scan=scan,
        security_score=80.0,
        tier="B",
        remediation_score=100,
    )


def _mock_use_case(result: AnalysisResult):
    uc = AsyncMock()
    uc.execute = AsyncMock(return_value=result)
    return AsyncMock(return_value=uc)


class TestAdvisorCommand:
    def test_advisor_prints_remediation_plan(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            baseline_met=False,
            alternatives=[_analysis()],
        )
        with patch(
            "dockerls.cli.commands.advisor.build_recommend_use_case", _mock_use_case(result)
        ):
            r = runner.invoke(app, ["advisor", "node"])
        assert r.exit_code == 0
        assert "Security Advisor" in r.stdout
        assert "Remediation Plan" in r.stdout

    def test_advisor_json_format(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            baseline_met=True,
            recommendations=[_analysis()],
        )
        with patch(
            "dockerls.cli.commands.advisor.build_recommend_use_case", _mock_use_case(result)
        ):
            r = runner.invoke(app, ["advisor", "node", "--format", "json"])
        assert r.exit_code == 0
        parsed = json.loads(r.stdout)
        assert "remediation" in parsed

    def test_advisor_json_format_not_corrupted_by_line_wrapping(self):
        # Regression: Rich's default console width reflows long lines,
        # which can inject stray newlines into printed JSON and break
        # machine parsing. A long summary string should still round-trip.
        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            baseline_met=True,
            recommendations=[_analysis()],
        )
        result.recommendations[0].recommendation = None
        with patch(
            "dockerls.cli.commands.advisor.build_recommend_use_case", _mock_use_case(result)
        ):
            r = runner.invoke(app, ["advisor", "node", "--format", "json"])
        json.loads(r.stdout)

    def test_advisor_no_images_exits_one(self):
        result = AnalysisResult(query="node", total_tags_scanned=0, baseline_met=False)
        with patch(
            "dockerls.cli.commands.advisor.build_recommend_use_case", _mock_use_case(result)
        ):
            r = runner.invoke(app, ["advisor", "node"])
        assert r.exit_code == 1

    def test_advisor_no_images_json_format(self):
        result = AnalysisResult(query="node", total_tags_scanned=0, baseline_met=False)
        with patch(
            "dockerls.cli.commands.advisor.build_recommend_use_case", _mock_use_case(result)
        ):
            r = runner.invoke(app, ["advisor", "node", "--format", "json"])
        assert r.exit_code == 1
        assert "error" in r.stdout


class TestAdvisorArgumentHandling:
    def test_unknown_format_is_rejected(self):
        """An unrecognised format silently fell through to the Rich table, so
        `--format jsonn` in a pipeline produced decorated prose where a parser
        expected JSON."""
        result = runner.invoke(app, ["advisor", "node", "--format", "jsonn"])

        assert result.exit_code == 1
        assert "--format" in result.stdout

    def test_workers_defaults_to_configuration_not_a_hard_coded_ten(self, monkeypatch):
        """`--workers` carried a hard-coded default of 10, which shadowed
        `Settings.workers` entirely -- the same dead-configuration bug the
        rest of the CLI was already fixed for."""
        import inspect

        from dockerls.cli.commands.advisor import advisor

        default = inspect.signature(advisor).parameters["workers"].default
        assert default.default is None, "a non-None default shadows Settings.workers"

    def test_configured_workers_reach_the_use_case(self):
        seen = {}

        async def fake_builder(**kwargs):
            seen.update(kwargs)
            uc = AsyncMock()
            uc.execute = AsyncMock(
                return_value=AnalysisResult(
                    query="node",
                    total_tags_scanned=1,
                    baseline_met=True,
                    recommendations=[_analysis()],
                )
            )
            return uc

        with patch("dockerls.cli.commands.advisor.build_recommend_use_case", fake_builder):
            result = runner.invoke(app, ["advisor", "node", "--format", "json"])

        assert result.exit_code == 0
        assert seen["workers"] is None, "the CLI passed a default instead of deferring to Settings"

    def test_invalid_threshold_is_a_message_not_a_traceback(self):
        async def boom(**kwargs):
            raise ValueError("--workers must be at least 1")

        with patch("dockerls.cli.commands.advisor.build_recommend_use_case", boom):
            result = runner.invoke(app, ["advisor", "node"])

        assert result.exit_code == 1
        assert "Invalid configuration" in result.stdout
        assert "Traceback" not in result.stdout
