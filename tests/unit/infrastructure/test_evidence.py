from __future__ import annotations

import json
from pathlib import Path

import pytest

from dockerls.infrastructure.evidence import EvidenceStore, _slugify


class TestSlugify:
    def test_reference_becomes_one_flat_segment(self):
        assert "/" not in _slugify("bitnami/node:22-debian")
        assert ":" not in _slugify("bitnami/node:22-debian")

    def test_traversal_cannot_escape_the_root(self):
        slug = _slugify("../../etc/passwd")
        assert ".." not in slug
        assert "/" not in slug

    def test_empty_reference_still_yields_a_name(self):
        assert _slugify("///") == "image"


class TestEvidenceStore:
    @pytest.mark.asyncio
    async def test_records_raw_scanner_json(self, tmp_path):
        store = EvidenceStore(tmp_path / "scans")
        raw = json.dumps({"Results": [{"Vulnerabilities": []}]})

        path = await store.record_scan("node:22-alpine", "trivy", raw)

        assert path
        assert json.loads((tmp_path / "scans").joinpath(path.split("/")[-1]).read_text()) == {
            "Results": [{"Vulnerabilities": []}]
        }
        assert "trivy" in path
        assert "node_22-alpine" in path

    @pytest.mark.asyncio
    async def test_two_scanners_produce_separate_files(self, tmp_path):
        store = EvidenceStore(tmp_path / "scans")
        a = await store.record_scan("node:22", "trivy", "{}")
        b = await store.record_scan("node:22", "grype", "{}")
        assert a != b
        assert len(list((tmp_path / "scans").iterdir())) == 2

    @pytest.mark.asyncio
    async def test_manifest_links_scores_to_evidence(self, tmp_path):
        store = EvidenceStore(tmp_path / "scans")
        scan_path = await store.record_scan("node:22", "trivy", "{}")

        manifest_path = await store.record_manifest(
            "node",
            [{"image": "node:22", "security_score": 97.5, "evidence": {"trivy": scan_path}}],
        )

        payload = json.loads(Path(manifest_path).read_text())
        assert payload["query"] == "node"
        assert payload["images"][0]["security_score"] == 97.5
        assert payload["images"][0]["evidence"]["trivy"] == scan_path

    @pytest.mark.asyncio
    async def test_unwritable_root_degrades_quietly(self, tmp_path):
        # A file where the directory should be makes mkdir fail; evidence is
        # an audit aid and must never take a scan down with it.
        blocker = tmp_path / "scans"
        blocker.write_text("not a directory")
        store = EvidenceStore(blocker)

        assert await store.record_scan("node:22", "trivy", "{}") == ""
        assert await store.record_manifest("node", []) == ""
