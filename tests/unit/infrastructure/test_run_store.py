"""Saved runs: addressed by id, never by path; private; validated on the way back in."""

from __future__ import annotations

import json
import os
import stat

import pytest

from dockerls.infrastructure.run_store import (
    RUN_ID,
    InvalidRunIdError,
    RunStore,
    scope_of,
    validate_run_id,
)

RESULT = {"query": "node", "recommendations": []}


def _save(store: RunStore, **overrides) -> str:
    kwargs = {
        "command": "recommend",
        "query": "node",
        "platform": "linux/amd64",
        "filters": "",
        "profile": "",
        "completeness": "COMPLETE",
        "result": RESULT,
        "summary": {},
        "version": "1.0.16",
    }
    kwargs.update(overrides)
    return store.save(**kwargs)


class TestRunIds:
    def test_a_generated_id_has_the_documented_shape(self):
        assert RUN_ID.fullmatch(RunStore.new_run_id())

    def test_ids_sort_by_time(self):
        from datetime import UTC, datetime

        early = RunStore.new_run_id(datetime(2026, 1, 1, tzinfo=UTC))
        late = RunStore.new_run_id(datetime(2026, 9, 30, tzinfo=UTC))
        assert early < late

    @pytest.mark.parametrize(
        "value",
        [
            "../../etc/passwd",
            "/etc/passwd",
            "20260930T131500Z-1a2b3c4d/../x",
            "20260930T131500Z-1A2B3C4D",
            "20260930T131500Z-1a2b3c4",
            "runs/20260930T131500Z-1a2b3c4d",
            "",
            "20260930T131500Z-1a2b3c4d\n../x",
            "~",
            "C:\\windows",
        ],
    )
    def test_anything_that_is_not_an_id_is_refused_before_touching_the_disk(self, value, tmp_path):
        with pytest.raises(InvalidRunIdError):
            validate_run_id(value)
        with pytest.raises(InvalidRunIdError):
            RunStore(tmp_path).load(value)


class TestSaveAndLoad:
    def test_a_saved_run_round_trips(self, tmp_path):
        store = RunStore(tmp_path / "runs")
        run_id = _save(store)

        document = store.load(run_id)

        assert document is not None
        assert document["run_id"] == run_id
        assert document["schema"] == "dockerls.run/1"
        assert document["result"] == RESULT
        assert document["platform"] == "linux/amd64"

    def test_files_are_private(self, tmp_path):
        store = RunStore(tmp_path / "runs")
        run_id = _save(store)

        mode = stat.S_IMODE(os.stat(store.root / f"{run_id}.json").st_mode)
        directory = stat.S_IMODE(os.stat(store.root).st_mode)
        assert mode == 0o600
        assert directory == 0o700

    def test_secrets_are_redacted_before_they_reach_the_disk(self, tmp_path):
        store = RunStore(tmp_path / "runs")
        run_id = _save(
            store,
            result={
                "error": (
                    "pull failed: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzIjoxfQ.abcdefghij"
                )
            },
            summary={"note": "token=hunter2secret"},
        )

        text = (store.root / f"{run_id}.json").read_text()

        assert "hunter2secret" not in text
        assert "eyJhbGciOiJIUzI1NiJ9" not in text

    def test_saving_never_leaves_a_partial_file_behind(self, tmp_path):
        store = RunStore(tmp_path / "runs")
        _save(store)
        assert [p.name for p in store.root.iterdir() if p.suffix != ".json"] == []

    def test_an_unwritable_store_returns_empty_and_does_not_raise(self, tmp_path):
        blocker = tmp_path / "file"
        blocker.write_text("x")
        assert _save(RunStore(blocker / "runs")) == ""

    def test_a_missing_run_is_none(self, tmp_path):
        assert RunStore(tmp_path).load("20260930T131500Z-1a2b3c4d") is None


class TestReadingIsDefensive:
    def test_a_document_that_is_not_json_is_treated_as_absent(self, tmp_path):
        store = RunStore(tmp_path)
        (tmp_path / "20260930T131500Z-1a2b3c4d.json").write_text("{not json")
        assert store.load("20260930T131500Z-1a2b3c4d") is None

    def test_the_wrong_schema_is_treated_as_absent(self, tmp_path):
        (tmp_path / "20260930T131500Z-1a2b3c4d.json").write_text(json.dumps({"schema": "other/9"}))
        assert RunStore(tmp_path).load("20260930T131500Z-1a2b3c4d") is None

    def test_a_document_claiming_another_id_is_rejected(self, tmp_path):
        store = RunStore(tmp_path)
        run_id = _save(store)
        other = "20260930T131500Z-00000000"
        (tmp_path / f"{other}.json").write_text((tmp_path / f"{run_id}.json").read_text())
        assert store.load(other) is None

    def test_a_symlink_is_never_followed(self, tmp_path):
        store = RunStore(tmp_path / "runs")
        run_id = _save(store)
        secret = tmp_path / "secret.json"
        secret.write_text((store.root / f"{run_id}.json").read_text())
        target = "20260930T131500Z-11111111"
        (store.root / f"{target}.json").symlink_to(secret)

        assert store.load(target) is None

    def test_an_oversized_document_is_ignored(self, tmp_path, monkeypatch):
        from dockerls.infrastructure import run_store

        store = RunStore(tmp_path)
        run_id = _save(store)
        monkeypatch.setattr(run_store, "MAX_DOCUMENT_BYTES", 10)
        assert store.load(run_id) is None


class TestRetention:
    def test_only_the_newest_runs_are_kept(self, tmp_path):
        from datetime import UTC, datetime, timedelta

        store = RunStore(tmp_path, retention=3)
        base = datetime(2026, 9, 1, tzinfo=UTC)
        ids = [
            _save(store, run_id=RunStore.new_run_id(base + timedelta(hours=i))) for i in range(5)
        ]

        assert store.ids() == list(reversed(ids[-3:]))

    def test_pruning_never_touches_files_that_are_not_runs(self, tmp_path):
        (tmp_path / "notes.json").write_text("{}")
        (tmp_path / "other.txt").write_text("keep")
        store = RunStore(tmp_path, retention=1)
        for _ in range(3):
            _save(store)

        assert (tmp_path / "notes.json").exists() and (tmp_path / "other.txt").exists()
        assert len(store.ids()) == 1


class TestScopes:
    def test_the_scope_is_the_question_platform_and_filters(self):
        base = {"command": "recommend", "query": "Node", "platform": "linux/amd64", "filters": ""}
        assert scope_of(base) == scope_of({**base, "query": "node"})
        assert scope_of(base) != scope_of({**base, "platform": "linux/arm64"})
        assert scope_of(base) != scope_of({**base, "filters": "distro=alpine"})
        assert scope_of(base) != scope_of({**base, "command": "analyze"})

    def test_the_previous_compatible_run_skips_incompatible_ones(self, tmp_path):
        from datetime import UTC, datetime, timedelta

        store = RunStore(tmp_path)
        base = datetime(2026, 9, 1, tzinfo=UTC)
        old = _save(store, run_id=RunStore.new_run_id(base))
        _save(store, platform="linux/arm64", run_id=RunStore.new_run_id(base + timedelta(hours=1)))
        current_id = _save(store, run_id=RunStore.new_run_id(base + timedelta(hours=2)))
        current = store.load(current_id)

        previous = store.previous_compatible(current, scope_of(current))

        assert previous is not None and previous["run_id"] == old
