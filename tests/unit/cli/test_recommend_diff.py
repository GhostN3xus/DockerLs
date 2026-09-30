"""`recommend --diff`: what moved since the previous run, and why."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis, MeasurementProvenance
from dockerls.cli.app import app
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.infrastructure.run_store import RunStore

runner = CliRunner()


def _result(digest: str, db: str, cves: list[str]) -> AnalysisResult:
    image = DockerImage(name="node", tag="22", digest="sha256:" + digest * 64)
    analysis = ImageAnalysis(
        image=image,
        scan=ScanResult(
            image_reference="node:22",
            scan_timestamp="2026-01-01T00:00:00Z",
            vulnerabilities=[
                Vulnerability(
                    cve_id=c,
                    severity=Severity.HIGH,
                    package_name="openssl",
                    installed_version="3.0.1",
                )
                for c in cves
            ],
        ),
        security_score=90.0,
        tier="B",
        remediation_score=70,
        provenance=MeasurementProvenance(scanner="trivy", scanner_version="0.60", db_revision=db),
    )
    return AnalysisResult(
        query="node",
        total_tags_scanned=1,
        total_tags_analyzed=1,
        baseline_met=True,
        recommendations=[analysis],
    )


@pytest.fixture
def store(tmp_path):
    runs = RunStore(tmp_path / "runs")
    with patch("dockerls.cli.commands.recommend.build_run_store", lambda: runs):
        yield runs


def _run(result, *args):
    uc = AsyncMock()
    uc.execute = AsyncMock(return_value=result)
    with patch(
        "dockerls.cli.commands.recommend.build_recommend_use_case", AsyncMock(return_value=uc)
    ):
        return runner.invoke(app, ["recommend", "node", "--no-progress", *args])


def test_a_new_image_with_new_findings_is_attributed_to_the_image(store):
    assert _run(_result("a", "2026-01-01T00:00:00+00:00", ["CVE-2026-1"])).exit_code == 0
    outcome = _run(
        _result("b", "2026-01-01T00:00:00+00:00", ["CVE-2026-1", "CVE-2026-2"]), "--diff"
    )
    assert outcome.exit_code == 0, outcome.output
    text = " ".join(outcome.output.split())
    assert "Since the previous run" in text
    assert "the image changed" in text
    assert "CVE-2026-2" in text


def test_same_bytes_new_database_is_attributed_to_the_database(store):
    _run(_result("a", "2026-01-01T00:00:00+00:00", ["CVE-2026-1"]))
    outcome = _run(
        _result("a", "2026-02-01T00:00:00+00:00", ["CVE-2026-1", "CVE-2026-9"]), "--diff"
    )
    text = " ".join(outcome.output.split())
    assert "the scanner's database changed" in text
    assert "CVE-2026-9" in text


def test_the_first_run_has_nothing_to_compare_and_says_so(store):
    outcome = _run(_result("a", "2026-01-01T00:00:00+00:00", []), "--diff")
    assert outcome.exit_code == 0
    assert "Since the previous run" in outcome.output


def test_without_the_flag_nothing_is_compared(store):
    _run(_result("a", "2026-01-01T00:00:00+00:00", []))
    outcome = _run(_result("b", "2026-01-01T00:00:00+00:00", []))
    assert "Since the previous run" not in outcome.output


def test_a_run_of_another_platform_is_not_compared(store):
    _run(_result("a", "2026-01-01T00:00:00+00:00", ["CVE-2026-1"]), "--platform", "linux/arm64")
    outcome = _run(_result("b", "2026-01-01T00:00:00+00:00", []), "--diff")
    text = " ".join(outcome.output.split())
    assert "Since the previous run" in text
    assert "the image changed" not in text


def test_json_format_carries_the_diff_as_data(store):
    _run(_result("a", "2026-01-01T00:00:00+00:00", ["CVE-2026-1"]), "--format", "json")
    outcome = _run(_result("b", "2026-01-01T00:00:00+00:00", []), "--format", "json", "--diff")
    document = json.loads(outcome.stdout)
    entry = document["diff"]["images"][0]
    assert entry["cause"] == "IMAGE_CHANGED"
    assert [f["cve_id"] for f in entry["removed"]] == ["CVE-2026-1"]
