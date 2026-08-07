"""Every output format renders the same `BuildReport`.

The property that matters is agreement: a build that prints "FAILED" to a
developer and uploads a clean SARIF to the security tab is worse than no
report at all, so the formats are checked against one another.
"""

import json

import pytest

from dockerls.application.dto.build import (
    BuildMetadata,
    BuildReport,
    BuildResult,
    FailingVulnerability,
    SbomInfo,
    ScannerSummary,
)
from dockerls.domain.entities.build_validation import (
    CheckStatus,
    ValidationCheck,
    ValidationResult,
)
from dockerls.domain.entities.hardening_rule import HardeningRule, Priority
from dockerls.domain.entities.vulnerability import Severity
from dockerls.exporters.build_report_exporter import BuildReportExporterFactory

FORMATS = ["json", "html", "sarif", "markdown"]


def _report(**overrides):
    defaults = {
        "build_id": "20260807T120000Z-abcd1234",
        "image": "myapp:1.0",
        "dockerfile_path": "/src/Dockerfile",
        "context_path": "/src",
        "status": "FAILED",
        "reason": "--fail-on high threshold exceeded",
        "validation": ValidationResult(
            dockerfile_path="/src/Dockerfile",
            checks=[
                ValidationCheck(
                    check="non_root_user",
                    title="Runs as a non-root user",
                    status=CheckStatus.FAIL,
                    severity=Severity.HIGH,
                    message="No USER directive in the final stage",
                    line=12,
                    fix="USER appuser",
                ),
                ValidationCheck(
                    check="healthcheck",
                    title="HEALTHCHECK declared",
                    status=CheckStatus.WARN,
                    severity=Severity.LOW,
                    message="No HEALTHCHECK",
                ),
                ValidationCheck(
                    check="no_sudo",
                    title="No sudo in the image",
                    status=CheckStatus.PASS,
                    severity=Severity.HIGH,
                    message="No sudo in the build",
                ),
                ValidationCheck(
                    check="dockerignore_present",
                    title=".dockerignore",
                    status=CheckStatus.SKIP,
                    message="No build context",
                ),
            ],
        ),
        "build": BuildResult(success=True, tag="myapp:1.0", size_bytes=1024 * 1024),
        "scans": [ScannerSummary(scanner="trivy", critical=0, high=2, medium=5, low=9, fixable=4)],
        "dockerfile_score": 83.0,
        "scan_score": 74.0,
        "security_score": 77.6,
        "security_tier": "B",
        "tier_advice": "conditional -- requires human review",
        "recommendations": [
            HardeningRule(
                rule_id="base_image_upgrade",
                title="A more hardened base image is available",
                priority=Priority.HIGH,
                current="node:22-alpine",
                suggested="cgr.dev/chainguard/node:latest",
                reason="Fewer packages to patch",
            )
        ],
        "failing_vulnerabilities": [
            FailingVulnerability(
                cve="CVE-2024-0001",
                severity="HIGH",
                package="openssl",
                installed_version="3.0.1",
                fixed_version="3.0.2",
                fixable=True,
            )
        ],
        "sbom": SbomInfo(
            fmt="cyclonedx", file="/src/.dockerls/sboms/app.json", components_count=156
        ),
        "build_metadata": BuildMetadata(
            timestamp="2026-08-07T12:00:00Z", git_sha="a1b2c3d4e5f6", built_by="ci@runner"
        ),
    }
    defaults.update(overrides)
    return BuildReport(**defaults)


class TestFactory:
    @pytest.mark.parametrize("fmt", [*FORMATS, "md"])
    def test_every_supported_format_can_be_created(self, fmt):
        assert BuildReportExporterFactory.create(fmt) is not None

    def test_format_names_are_case_insensitive(self):
        assert BuildReportExporterFactory.create("JSON") is not None

    def test_an_unknown_format_lists_the_alternatives(self):
        with pytest.raises(ValueError, match="Supported:"):
            BuildReportExporterFactory.create("pdf")

    def test_supported_formats_is_what_the_factory_actually_accepts(self):
        for fmt in BuildReportExporterFactory.supported_formats():
            assert BuildReportExporterFactory.create(fmt) is not None


class TestAllFormats:
    @pytest.mark.parametrize("fmt", FORMATS)
    def test_renders_without_raising(self, fmt):
        assert BuildReportExporterFactory.create(fmt).export_string(_report())

    @pytest.mark.parametrize("fmt", FORMATS)
    def test_writes_to_a_file(self, tmp_path, fmt):
        target = tmp_path / f"report.{fmt}"
        BuildReportExporterFactory.create(fmt).export(_report(), target)
        assert target.read_text()

    @pytest.mark.parametrize("fmt", ["json", "html", "markdown"])
    def test_every_human_format_states_the_failure(self, fmt):
        """A format that renders a failed build without saying so is the
        one bug that makes the whole gate pointless."""
        out = BuildReportExporterFactory.create(fmt).export_string(_report())
        assert "FAILED" in out

    @pytest.mark.parametrize("fmt", FORMATS)
    def test_a_report_with_nothing_in_it_still_renders(self, fmt):
        minimal = BuildReport(build_id="x", validation=ValidationResult())
        assert BuildReportExporterFactory.create(fmt).export_string(minimal)


class TestJSON:
    def test_is_valid_json_with_the_documented_top_level_keys(self):
        data = json.loads(BuildReportExporterFactory.create("json").export_string(_report()))
        for key in (
            "build_id",
            "image",
            "validation",
            "scans",
            "security_score",
            "security_tier",
            "recommendations",
            "sbom",
            "build_metadata",
        ):
            assert key in data, f"CI pipelines parse `{key}`; it must stay in the payload"

    def test_check_details_survive_serialisation(self):
        data = json.loads(BuildReportExporterFactory.create("json").export_string(_report()))
        check = data["validation"]["checks"][0]
        assert check["check"] == "non_root_user"
        assert check["status"] == "FAIL"
        assert check["line"] == 12


class TestHTML:
    def test_is_a_complete_document(self):
        out = BuildReportExporterFactory.create("html").export_string(_report())
        assert out.startswith("<!DOCTYPE html>")
        assert out.rstrip().endswith("</html>")

    def test_escapes_content_that_could_close_a_tag(self):
        report = _report(image="<script>alert(1)</script>")
        out = BuildReportExporterFactory.create("html").export_string(report)
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;" in out

    def test_says_plainly_when_no_scan_ran(self):
        out = BuildReportExporterFactory.create("html").export_string(
            _report(scans=[], scan_score=None)
        )
        assert "No post-build scan was run" in out


class TestMarkdown:
    def test_table_cells_cannot_be_broken_by_a_pipe(self):
        report = _report()
        report.validation.checks[0].message = "a | b | c"
        out = BuildReportExporterFactory.create("markdown").export_string(report)
        assert "a \\| b \\| c" in out

    def test_counts_agree_with_the_validation_result(self):
        out = BuildReportExporterFactory.create("markdown").export_string(_report())
        assert "1 passed, 1 warning(s), 1 error(s)" in out


class TestSARIF:
    def _sarif(self, report=None):
        return json.loads(
            BuildReportExporterFactory.create("sarif").export_string(report or _report())
        )

    def test_declares_the_expected_schema_version(self):
        assert self._sarif()["version"] == "2.1.0"

    def test_reports_findings_and_vulnerabilities(self):
        results = self._sarif()["runs"][0]["results"]
        rule_ids = {r["ruleId"] for r in results}
        assert "non_root_user" in rule_ids
        assert "CVE-2024-0001" in rule_ids

    def test_passing_checks_are_not_reported_as_problems(self):
        rule_ids = {r["ruleId"] for r in self._sarif()["runs"][0]["results"]}
        assert "no_sudo" not in rule_ids
        assert "dockerignore_present" not in rule_ids

    def test_severity_maps_to_the_sarif_level(self):
        by_rule = {r["ruleId"]: r["level"] for r in self._sarif()["runs"][0]["results"]}
        assert by_rule["non_root_user"] == "error"
        assert by_rule["healthcheck"] == "note"

    def test_line_numbers_are_one_based(self):
        """SARIF rejects startLine 0, so a file-level finding must anchor to
        line 1 rather than to nothing."""
        for result in self._sarif()["runs"][0]["results"]:
            region = result["locations"][0]["physicalLocation"].get("region")
            if region:
                assert region["startLine"] >= 1

    def test_the_location_is_repository_relative(self):
        """GitHub places annotations by repo-relative path; an absolute one
        silently produces no annotation at all."""
        uri = self._sarif()["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]
        assert uri == "Dockerfile"
        assert not uri.startswith("/")
