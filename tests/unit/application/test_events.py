"""The event stream's own rules: provisional vs final, clean output, no secrets."""

from __future__ import annotations

import io
import json

import pytest

from dockerls.application.services.events import (
    EVENT_SCHEMA,
    EventStream,
    ListSink,
    NdjsonSink,
    redact_values,
)


class TestProvisionalVersusFinal:
    def test_every_event_says_which_it_is_and_carries_the_schema(self):
        sink = ListSink()
        stream = EventStream([sink], command="recommend", run_id="20260930T000000Z-aaaaaaaa")

        stream.emit("ranking", provisional=True, revision=1, items=[])
        stream.emit("run_finished", final=True, status="COMPLETE")

        first, last = sink.events
        assert first["schema"] == EVENT_SCHEMA == "dockerls.events/1"
        assert (first["provisional"], first["final"]) == (True, False)
        assert (last["provisional"], last["final"]) == (False, True)
        assert first["run_id"] == last["run_id"] == "20260930T000000Z-aaaaaaaa"
        assert [e["seq"] for e in sink.events] == [1, 2]

    def test_nothing_can_follow_the_final_event(self):
        stream = EventStream([ListSink()])
        stream.emit("run_finished", final=True, status="COMPLETE")

        with pytest.raises(RuntimeError, match="after the final event"):
            stream.emit("phase", name="late")

    def test_an_event_cannot_be_both_provisional_and_final(self):
        with pytest.raises(ValueError, match="both provisional and final"):
            EventStream([ListSink()]).emit("ranking", provisional=True, final=True)

    def test_pending_checks_travel_with_the_event(self):
        sink = ListSink()
        EventStream([sink]).emit("ranking", provisional=True, pending=["cross-validation"])

        assert sink.events[0]["pending_checks"] == ["cross-validation"]

    def test_ranking_revisions_count_up(self):
        stream = EventStream([ListSink()])
        assert [stream.next_revision() for _ in range(3)] == [1, 2, 3]

    def test_a_stream_with_no_sinks_is_inert_and_never_complains(self):
        stream = EventStream()
        assert not stream.enabled
        stream.emit("run_finished", final=True)
        stream.emit("phase")  # no sink, so no "after final" bookkeeping either


class TestNdjsonIsClean:
    def test_every_line_is_one_json_object_and_nothing_else(self):
        out = io.StringIO()
        stream = EventStream([NdjsonSink(out)], command="analyze")

        stream.emit("run_started", query="node:22")
        stream.emit("phase", name="Scanning\nwith a newline and \x1b[31mANSI\x1b[0m")
        stream.emit("run_finished", final=True, status="COMPLETE")

        lines = out.getvalue().splitlines()
        assert len(lines) == 3
        parsed = [json.loads(line) for line in lines]
        assert [p["type"] for p in parsed] == ["run_started", "phase", "run_finished"]
        assert all(isinstance(p, dict) for p in parsed)

    def test_the_output_is_flushed_per_event(self):
        class Recording(io.StringIO):
            flushes = 0

            def flush(self) -> None:
                type(self).flushes += 1
                super().flush()

        out = Recording()
        stream = EventStream([NdjsonSink(out)])
        stream.emit("phase", name="a")
        stream.emit("phase", name="b")

        assert Recording.flushes == 2, "a consumer must see each event as it happens"

    def test_a_closed_pipe_stops_the_writing_but_not_the_run(self):
        class Broken(io.StringIO):
            def write(self, text: str) -> int:
                raise BrokenPipeError

        stream = EventStream([NdjsonSink(Broken())])
        stream.emit("phase", name="a")  # must not raise
        stream.emit("run_finished", final=True)

    def test_non_finite_numbers_cannot_produce_invalid_json(self):
        out = io.StringIO()
        with pytest.raises(ValueError, match="not JSON compliant"):
            EventStream([NdjsonSink(out)]).emit("phase", value=float("nan"))


class TestSecretsNeverLeave:
    SECRETS = [
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk",
        "token=abc123secretvalue",
        "https://user:hunter2@registry.example/v2/",
        "dckr_pat_abcdefghijklmnop",
        "password: hunter2",
    ]

    def test_string_values_are_redacted_at_any_depth(self):
        cleaned = redact_values({"a": {"b": [self.SECRETS[0], {"c": self.SECRETS[1]}]}})
        text = json.dumps(cleaned)
        assert "abc123secretvalue" not in text
        assert "eyJhbGci" not in text

    @pytest.mark.parametrize("secret", SECRETS)
    def test_a_secret_in_an_event_never_reaches_the_stream(self, secret):
        out = io.StringIO()
        EventStream([NdjsonSink(out)]).emit("phase", name=f"pull failed: {secret}")

        written = out.getvalue()
        for needle in ("hunter2", "abc123secretvalue", "eyJhbGci", "dckr_pat_abcdefghijklmnop"):
            assert needle not in written
        assert json.loads(written)["type"] == "phase", "redaction must not break the JSON"

    def test_keys_and_structure_are_left_alone(self):
        assert redact_values({"authors": ["x"], "n": 3, "ok": True}) == {
            "authors": ["x"],
            "n": 3,
            "ok": True,
        }
