"""`export --run`: the same result in another format, with no new measurement."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis, MeasurementProvenance
from dockerls.cli.app import app
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.infrastructure.run_store import RunStore

runner = CliRunner()
DIGEST = "sha256:" + "c" * 64


def _result() -> AnalysisResult:
    analysis = ImageAnalysis(
        image=DockerImage(
            name="node",
            tag="22",
            digest=DIGEST,
            platform="linux/arm64",
            identity_status="CONFIRMED",
            index_digest="sha256:" + "d" * 64,
        ),
        scan=ScanResult(
            image_reference=f"node@{DIGEST}",
            scan_timestamp="2026-09-30T10:00:00+00:00",
            evidence_path="/evidence/node.json",
            platform="linux/arm64",
        ),
        security_score=90.0,
        tier="B",
        remediation_score=70,
        provenance=MeasurementProvenance(
            origin="cache",
            requested_reference="node:22",
            resolved_reference=f"node@{DIGEST}",
            measured_reference=f"node@{DIGEST}",
            platform="linux/arm64",
            db_revision="2026-09-30T00:00:00+00:00",
        ),
        evidence_paths={"trivy": "/evidence/node.json"},
    )
    return AnalysisResult(
        query="node",
        total_tags_scanned=1,
        total_tags_analyzed=1,
        baseline_met=True,
        recommendations=[analysis],
    )


@pytest.fixture
def saved(tmp_path, monkeypatch):
    store = RunStore(tmp_path / "runs")
    result = _result()
    run_id = store.save(
        command="recommend",
        query="node",
        platform="linux/arm64",
        filters="",
        profile="",
        completeness="COMPLETE",
        result=result.model_dump(mode="json"),
        summary={},
        version="1.0.16",
    )
    monkeypatch.setattr("dockerls.cli.commands.export.build_run_store", lambda: store)
    return run_id, store


def _export(*args):
    # Any attempt to measure would build a use case; make that impossible.
    boom = AsyncMock(side_effect=AssertionError("a saved run must never trigger a scan"))
    with patch("dockerls.cli.commands.export.build_recommend_use_case", boom):
        return runner.invoke(app, ["export", *args])


def test_a_saved_run_is_exported_without_measuring(saved):
    run_id, _ = saved

    outcome = _export("--run", run_id, "--format", "json")

    assert outcome.exit_code == 0, outcome.output
    payload = json.loads(outcome.stdout)
    assert payload["saved_run"]["run_id"] == run_id
    assert payload["saved_run"]["rescanned"] is False


def test_identity_evidence_and_metadata_survive_the_round_trip(saved):
    run_id, _ = saved

    payload = json.loads(_export("--run", run_id, "--format", "json").stdout)

    best = payload["recommendations"][0]
    assert best["image"]["digest"] == DIGEST
    assert best["image"]["platform"] == "linux/arm64"
    assert best["image"]["index_digest"] == "sha256:" + "d" * 64
    assert best["evidence_paths"] == {"trivy": "/evidence/node.json"}
    assert best["provenance"]["db_revision"] == "2026-09-30T00:00:00+00:00"
    assert best["provenance"]["origin"] == "cache"


@pytest.mark.parametrize("fmt", ["json", "csv", "markdown", "html", "sarif"])
def test_the_existing_formats_all_work_from_a_saved_run(saved, fmt):
    run_id, _ = saved
    outcome = _export("--run", run_id, "--format", fmt)
    assert outcome.exit_code == 0, outcome.output
    assert outcome.stdout.strip()


def test_output_goes_to_the_requested_file(saved, tmp_path):
    run_id, _ = saved
    target = tmp_path / "out" / "report.json"

    outcome = _export("--run", run_id, "--output", str(target))

    assert outcome.exit_code == 0
    assert json.loads(target.read_text())["saved_run"]["run_id"] == run_id


class TestTheRunIdIsNotAPath:
    @pytest.mark.parametrize(
        "value",
        ["../../etc/passwd", "/etc/passwd", "20260930T131500Z-1a2b3c4d/../x", "not-an-id"],
    )
    def test_a_path_is_refused_as_an_id(self, saved, value):
        outcome = _export("--run", value)
        assert outcome.exit_code == 1
        assert "run id looks like" in " ".join(outcome.output.split())

    def test_an_unknown_id_is_a_clear_error(self, saved):
        outcome = _export("--run", "20260930T131500Z-00000000")
        assert outcome.exit_code == 1
        assert "no saved run" in outcome.output


class TestOutputPathIsValidated:
    def test_a_directory_is_refused(self, saved, tmp_path):
        run_id, _ = saved
        outcome = _export("--run", run_id, "--output", str(tmp_path))
        assert outcome.exit_code == 1
        assert "not a regular file" in " ".join(outcome.output.split())

    def test_a_symlink_is_refused(self, saved, tmp_path):
        run_id, _ = saved
        real = tmp_path / "real.txt"
        real.write_text("keep")
        link = tmp_path / "link.json"
        link.symlink_to(real)

        outcome = _export("--run", run_id, "--output", str(link))

        assert outcome.exit_code == 1
        assert real.read_text() == "keep", "the write went through the symlink"


def test_a_run_with_a_schema_this_version_cannot_read_is_an_error(saved, tmp_path):
    run_id, store = saved
    path = store.root / f"{run_id}.json"
    document = json.loads(path.read_text())
    document["result"] = {"recommendations": "not a list"}
    path.write_text(json.dumps(document))

    outcome = _export("--run", run_id)

    assert outcome.exit_code == 1
    assert "does not match" in " ".join(outcome.output.split())


def test_an_image_and_a_run_together_are_refused():
    outcome = _export("node", "--run", "20260930T131500Z-1a2b3c4d")
    assert outcome.exit_code == 1


def test_neither_an_image_nor_a_run_is_refused():
    assert _export().exit_code == 1


def test_secrets_in_a_saved_run_are_not_in_the_export(tmp_path, monkeypatch):
    store = RunStore(tmp_path / "runs")
    result = _result().model_dump(mode="json")
    result["errors"] = ["pull failed: token=hunter2secret"]
    run_id = store.save(
        command="recommend",
        query="node",
        platform="linux/amd64",
        filters="",
        profile="",
        completeness="COMPLETE",
        result=result,
        summary={},
        version="1.0.16",
    )
    monkeypatch.setattr("dockerls.cli.commands.export.build_run_store", lambda: store)

    outcome = _export("--run", run_id)

    assert "hunter2secret" not in outcome.stdout
