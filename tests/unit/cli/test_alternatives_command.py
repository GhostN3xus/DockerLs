"""`dockerls alternatives`: the CLI contract, including its refusals.

The behaviour worth pinning is what the command does when it *cannot*
answer. An unscannable current image means there is no baseline to improve
on, and the command has to say so and exit 1 rather than presenting
candidates against nothing.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from dockerls.application.dto.analysis import AnalysisResult, DimensionReport, ImageAnalysis
from dockerls.application.services.source_registry import UnknownSourceError
from dockerls.cli.app import app
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.value_objects.confidence import Confidence

runner = CliRunner()


def _analysis(
    name: str = "node",
    tag: str = "22",
    *,
    score: float = 70.0,
    critical: int = 0,
    source: str = "Docker Hub",
    os_family: str = "debian",
    digest: str = "",
) -> ImageAnalysis:
    vulns = [
        Vulnerability(
            cve_id=f"CVE-2024-{i}",
            severity=Severity.CRITICAL,
            package_name="openssl",
            installed_version="1.0",
        )
        for i in range(critical)
    ]
    return ImageAnalysis(
        image=DockerImage(name=name, tag=tag, source=source, digest=digest),
        scan=ScanResult(
            image_reference=f"{name}:{tag}",
            vulnerabilities=vulns,
            status=ScanStatus.OK,
            scan_timestamp="2026-01-01T00:00:00Z",
            os_family=os_family,
        ),
        security_score=score,
        tier="B",
        remediation_score=80,
        confidence=Confidence.HIGH,
        hardening=DimensionReport(score=70.0, coverage=0.6, reportable=True),
        attack_surface=DimensionReport(score=30.0, coverage=0.6, reportable=True),
    )


def _patched(current: ImageAnalysis | None, result: AnalysisResult):
    analyze = AsyncMock()
    analyze.execute = (
        AsyncMock(return_value=current)
        if current is not None
        else AsyncMock(side_effect=ValueError("scan status is ERROR"))
    )
    recommend = AsyncMock()
    recommend.execute = AsyncMock(return_value=result)
    return (
        patch(
            "dockerls.cli.commands.alternatives.build_analyze_use_case",
            AsyncMock(return_value=analyze),
        ),
        patch(
            "dockerls.cli.commands.alternatives.build_recommend_use_case",
            AsyncMock(return_value=recommend),
        ),
    )


def _run(current, result, args):
    analyze_patch, recommend_patch = _patched(current, result)
    with analyze_patch, recommend_patch:
        return runner.invoke(app, args)


class TestAlternativesOutput:
    def test_it_names_the_current_image_and_the_alternatives(self):
        current = _analysis("node", "22", score=55.0, critical=2)
        better = _analysis("node", "22-bookworm-slim", score=88.0)
        result = AnalysisResult(
            query="node", total_tags_scanned=5, baseline_met=True, recommendations=[better]
        )

        outcome = _run(current, result, ["alternatives", "node:22", "--no-progress"])

        assert outcome.exit_code == 0
        assert "CURRENT" in outcome.stdout
        assert "node:22" in outcome.stdout
        assert "22-bookworm-slim" in outcome.stdout
        assert "RECOMMENDED ALTERNATIVES" in outcome.stdout

    def test_it_shows_the_score_delta_and_the_reasons(self):
        current = _analysis("node", "22", score=55.0, critical=2)
        better = _analysis("node", "22-slim", score=88.0)
        result = AnalysisResult(
            query="node", total_tags_scanned=5, baseline_met=True, recommendations=[better]
        )

        outcome = _run(current, result, ["alternatives", "node:22", "--no-progress"])
        assert "+33.0" in outcome.stdout
        assert "WHY" in outcome.stdout
        assert "CRITICAL: 2 -> 0" in outcome.stdout

    def test_it_always_prints_the_migration_checklist(self):
        current = _analysis("node", "22-alpine", os_family="alpine")
        better = _analysis("node", "22-bookworm-slim", score=90.0, os_family="debian")
        result = AnalysisResult(
            query="node", total_tags_scanned=5, baseline_met=True, recommendations=[better]
        )

        outcome = _run(current, result, ["alternatives", "node:22-alpine", "--no-progress"])
        assert "MIGRATION CHECKLIST" in outcome.stdout
        assert "TRADE-OFFS" in outcome.stdout
        # The musl/glibc warning is the whole reason this section exists.
        assert "musl" in outcome.stdout

    def test_it_says_so_plainly_when_nothing_beats_the_current_image(self):
        current = _analysis("node", "22", score=95.0)
        result = AnalysisResult(
            query="node",
            total_tags_scanned=5,
            baseline_met=True,
            recommendations=[_analysis("node", "22", score=95.0)],
        )

        outcome = _run(current, result, ["alternatives", "node:22", "--no-progress"])
        assert "No alternative scored better" in outcome.stdout
        assert outcome.exit_code == 0


class TestAlternativesRefusals:
    def test_an_unscannable_current_image_is_a_technical_failure(self):
        """No baseline means no improvement can be claimed. Exit 1."""
        result = AnalysisResult(
            query="node",
            total_tags_scanned=5,
            baseline_met=True,
            recommendations=[_analysis("node", "22-slim", score=90.0)],
        )
        outcome = _run(None, result, ["alternatives", "node:22", "--no-progress"])

        assert outcome.exit_code == 1
        assert "could not be scanned" in outcome.stdout
        assert "not a verdict" in outcome.stdout

    def test_unverified_candidates_are_never_offered(self):
        current = _analysis("node", "22", score=50.0)
        unverified = _analysis("dhi.io/node", "22-debian13", score=99.0, source="DHI")
        unverified.confidence = Confidence.UNVERIFIED
        result = AnalysisResult(
            query="node", total_tags_scanned=5, baseline_met=True, recommendations=[unverified]
        )

        outcome = _run(current, result, ["alternatives", "node:22", "--no-progress"])
        assert "dhi.io/node" not in outcome.stdout
        assert "No alternative scored better" in outcome.stdout

    def test_an_unknown_source_is_rejected_with_the_valid_names(self):
        current = _analysis("node", "22")
        result = AnalysisResult(query="node", total_tags_scanned=0, baseline_met=False)
        analyze_patch, recommend_patch = _patched(current, result)
        with (
            analyze_patch,
            patch(
                "dockerls.cli.commands.alternatives.build_recommend_use_case",
                AsyncMock(side_effect=UnknownSourceError(["nope"], ["dockerhub", "dhi"])),
            ),
        ):
            outcome = runner.invoke(
                app, ["alternatives", "node:22", "--source", "nope", "--no-progress"]
            )

        assert outcome.exit_code == 1
        assert "nope" in outcome.stdout
        assert "dockerhub" in outcome.stdout


class TestAlternativesJson:
    def test_the_json_payload_carries_the_migration_plan(self):
        current = _analysis("node", "22", score=55.0, critical=1)
        better = _analysis(
            "node", "22-slim", score=88.0, digest="sha256:" + "e" * 64, os_family="debian"
        )
        result = AnalysisResult(
            query="node", total_tags_scanned=5, baseline_met=True, recommendations=[better]
        )

        outcome = _run(current, result, ["alternatives", "node:22", "-f", "json"])
        payload = json.loads(outcome.stdout)

        assert payload["current"]["image"]["tag"] == "22"
        entry = payload["alternatives"][0]
        assert entry["image"]["image"]["tag"] == "22-slim"
        assert entry["migration"]["score_delta"] == 33.0
        assert entry["migration"]["to_pinned_reference"].endswith("e" * 64)
        assert entry["migration"]["checklist"]

    def test_json_reports_the_failure_rather_than_an_empty_result(self):
        result = AnalysisResult(query="node", total_tags_scanned=0, baseline_met=False)
        outcome = _run(None, result, ["alternatives", "node:22", "-f", "json"])
        payload = json.loads(outcome.stdout)
        assert "error" in payload
        assert outcome.exit_code == 1
