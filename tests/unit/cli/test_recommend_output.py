"""Terminal output contract for `dockerls recommend`.

Covers the three promises the table makes to the reader: the run summary is
always shown, unverified images are quarantined into their own section, and
every recommended row carries a working Docker Hub link.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis, UnverifiedImage
from dockerls.cli.app import app
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult

runner = CliRunner()


def _analysis(tag="22-alpine", score=95.0, divergence="", hub_verified=True, name="node"):
    image = DockerImage(name=name, tag=tag)
    return ImageAnalysis(
        image=image,
        scan=ScanResult(
            image_reference=image.full_reference, scan_timestamp="2026-01-01T00:00:00Z"
        ),
        security_score=score,
        tier="A",
        remediation_score=100,
        scan_divergence=divergence,
        hub_url=f"https://hub.docker.com/_/{name}?tab=tags&name={tag}",
        hub_tag_verified=hub_verified,
    )


def _run(result: AnalysisResult, *args: str):
    uc = AsyncMock()
    uc.execute = AsyncMock(return_value=result)
    with patch(
        "dockerls.cli.commands.recommend.build_recommend_use_case",
        AsyncMock(return_value=uc),
    ):
        return runner.invoke(app, ["recommend", "node", "--no-progress", *args])


class TestRunSummary:
    def test_summary_reports_analyzed_and_skipped_counts(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=24,
            total_tags_analyzed=12,
            baseline_met=True,
            recommendations=[_analysis()],
            unverified=[
                UnverifiedImage(image_reference=f"node:t{i}", status="ERROR", reason="exit 1")
                for i in range(12)
            ],
            log_file="logs/dockerls_2026-01-01_00-00-00.log",
        )
        out = _run(result).stdout
        assert "12/24 analyzed" in out
        assert "12 skipped (technical error)" in out
        assert "logs/dockerls_2026-01-01_00-00-00.log" in out

    def test_summary_omits_skip_count_when_nothing_failed(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=3,
            total_tags_analyzed=3,
            baseline_met=True,
            recommendations=[_analysis()],
            log_file="logs/run.log",
        )
        out = _run(result).stdout
        assert "3/3 analyzed" in out
        assert "skipped" not in out


class TestUnverifiedSection:
    def test_failed_images_are_listed_separately(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=2,
            total_tags_analyzed=1,
            baseline_met=True,
            recommendations=[_analysis(tag="22-alpine")],
            unverified=[
                UnverifiedImage(
                    image_reference="node:26.7-slim",
                    status="ERROR",
                    reason="cache may be in use by another process: timeout",
                )
            ],
        )
        out = _run(result).stdout
        assert "Unverified (technical error)" in out
        assert "node:26.7-slim" in out

    def test_failed_image_never_appears_in_the_recommended_table(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=2,
            total_tags_analyzed=1,
            baseline_met=True,
            recommendations=[_analysis(tag="22-alpine")],
            unverified=[
                UnverifiedImage(image_reference="node:26.7-slim", status="ERROR", reason="exit 1")
            ],
        )
        out = _run(result).stdout
        recommended_block = out.split("Unverified (technical error)")[0]
        assert "node:22-alpine" in recommended_block
        assert "node:26.7-slim" not in recommended_block

    def test_no_section_when_everything_scanned(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            total_tags_analyzed=1,
            baseline_met=True,
            recommendations=[_analysis()],
        )
        assert "Unverified" not in _run(result).stdout


class TestDockerHubLinks:
    def test_official_image_link_is_listed(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            total_tags_analyzed=1,
            baseline_met=True,
            recommendations=[_analysis(tag="26.7-slim")],
        )
        out = _run(result).stdout
        assert "Docker Hub" in out
        assert "hub.docker.com/_/node?tab=tags&name=26.7-slim" in out

    def test_third_party_image_link_is_listed(self):
        analysis = _analysis(name="bitnami/node", tag="22")
        analysis.hub_url = "https://hub.docker.com/r/bitnami/node/tags?name=22"
        result = AnalysisResult(
            query="bitnami/node",
            total_tags_scanned=1,
            total_tags_analyzed=1,
            baseline_met=True,
            recommendations=[analysis],
        )
        assert "hub.docker.com/r/bitnami/node/tags?name=22" in _run(result).stdout


class TestDivergenceRendering:
    def test_disputed_score_replaces_the_number(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            total_tags_analyzed=1,
            baseline_met=True,
            recommendations=[
                _analysis(score=95.0, divergence="HIGH trivy=0 vs grype=10"),
            ],
        )
        out = _run(result).stdout
        assert "disputed" in out
        assert "95.0" not in out
        assert "Scanner divergence" in out
        assert "trivy=0 vs grype=10" in out

    def test_undisputed_score_is_shown_as_a_number(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            total_tags_analyzed=1,
            baseline_met=True,
            recommendations=[_analysis(score=95.0)],
        )
        out = _run(result).stdout
        assert "95.0" in out
        assert "disputed" not in out


class TestJsonOutputCarriesVerificationData:
    def test_json_includes_unverified_and_counts(self):
        import json

        result = AnalysisResult(
            query="node",
            total_tags_scanned=2,
            total_tags_analyzed=1,
            baseline_met=True,
            recommendations=[_analysis()],
            unverified=[
                UnverifiedImage(image_reference="node:26.7-slim", status="ERROR", reason="exit 1")
            ],
            log_file="logs/run.log",
        )
        parsed = json.loads(_run(result, "--format", "json").stdout)
        assert parsed["total_tags_analyzed"] == 1
        assert parsed["unverified"][0]["image_reference"] == "node:26.7-slim"
        assert parsed["recommendations"][0]["hub_tag_verified"] is True
        assert parsed["log_file"] == "logs/run.log"


class TestTierWarningsAreSurfaced:
    """`SecurityTier.production_ready` existed but was never read, and the
    README's tier obligations were nowhere in the terminal output. A reader of
    the table had no way to know a row needs human review.

    Na escala A-F, C é o tier condicional (exige revisão) e D/E/F não são
    production-ready; A e B passam sem aviso.
    """

    def _tiered(self, tier, production_ready=True):
        a = _analysis()
        a.tier = tier
        a.production_ready = production_ready
        return a

    def _out(self, *analyses):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=len(analyses),
            total_tags_analyzed=len(analyses),
            baseline_met=False,
            alternatives=list(analyses),
        )
        return _run(result).stdout

    def test_tier_c_is_flagged_as_needing_review(self):
        out = self._out(self._tiered("C"))
        assert "Requires review" in out
        assert "Tier C" in out
        assert "human review before production" in " ".join(out.split())

    @pytest.mark.parametrize("tier", ["D", "E", "F"])
    def test_low_tiers_are_flagged_as_not_production_ready(self, tier):
        out = self._out(self._tiered(tier, production_ready=False))
        assert "not production ready" in out

    @pytest.mark.parametrize("tier", ["A", "B"])
    def test_production_ready_tiers_get_no_warning(self, tier):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=1,
            total_tags_analyzed=1,
            baseline_met=True,
            recommendations=[self._tiered(tier)],
        )
        assert "Requires review" not in _run(result).stdout

    def test_warning_names_the_specific_image(self):
        good, risky = _analysis(tag="22-alpine"), self._tiered("C")
        risky.image = DockerImage(name="node", tag="18-bookworm")
        out = self._out(good, risky)
        block = out.split("Requires review")[1]
        assert "node:18-bookworm" in block
        assert "node:22-alpine" not in block
