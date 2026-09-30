"""Progressive results: provisional first, revised when the evidence says so,
and exactly one final event that states how complete the run was."""

from __future__ import annotations

import contextlib
import io
import json

from dockerls.application.services.events import EventStream, NdjsonSink
from dockerls.domain.value_objects.execution_profile import Enrichment
from tests.unit.application.recommend_harness import FakeIntel, World, stream


def _types(sink) -> list[str]:
    return [e["type"] for e in sink.events]


async def test_a_provisional_ranking_is_shown_before_threat_intelligence_arrives():
    world = World()
    world.add("22", 1)
    world.add("20", 1)
    events, sink = stream()

    await world.use_case(threat_intel=FakeIntel(), events=events).execute("node")

    types = _types(sink)
    assert types[0] == "run_started"
    assert types.index("candidate_measured") < types.index("ranking") < types.index("run_finished")
    provisional = next(e for e in sink.events if e["type"] == "ranking")
    assert provisional["provisional"] is True and provisional["final"] is False
    assert "threat intelligence enrichment" in provisional["pending_checks"]
    assert [i["reference"] for i in provisional["items"]] == ["node:22", "node:20"]


async def test_a_later_enrichment_can_revise_the_ranking_and_says_so():
    world = World()
    exploited = world.add("22", 1)
    world.add("20", 1)
    # The first candidate's only finding turns out to be exploited in the wild.
    kev = f"CVE-2026-{world.scanner.cve_offsets[exploited]:04d}"
    events, sink = stream()

    result = await world.use_case(threat_intel=FakeIntel({kev}), events=events).execute("node")

    revised = [e for e in sink.events if e["type"] == "ranking_revised"]
    assert len(revised) == 1
    assert revised[0]["provisional"] is True
    assert [i["reference"] for i in revised[0]["previous"]] == ["node:22", "node:20"]
    assert [i["reference"] for i in revised[0]["items"]] == ["node:20", "node:22"]
    assert (
        revised[0]["revision"] > next(e for e in sink.events if e["type"] == "ranking")["revision"]
    )
    # ... and the final answer is the revised one, not the provisional one.
    top = (result.recommendations or result.alternatives)[0]
    assert top.image.full_reference == "node:20"


async def test_exactly_one_final_event_and_it_is_last():
    world = World()
    world.add("22", 0)
    events, sink = stream()

    await world.use_case(threat_intel=FakeIntel(), events=events).execute("node")

    finals = [e for e in sink.events if e["final"]]
    assert len(finals) == 1
    assert sink.events[-1] is finals[0]
    assert finals[0]["type"] == "run_finished"
    assert finals[0]["status"] == "COMPLETE"
    assert finals[0]["result"]["query"] == "node"
    assert not any(e["final"] for e in sink.events[:-1])


async def test_a_run_that_never_finished_is_cancelled_not_complete():
    import asyncio

    world = World()
    world.add("22", 0)
    world.scanner.latency = 30
    events, sink = stream()
    use_case = world.use_case(events=events)

    task = asyncio.ensure_future(use_case.execute("node"))
    await asyncio.sleep(0.3)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task

    final = sink.events[-1]
    assert (final["type"], final["final"], final["status"]) == ("run_finished", True, "CANCELLED")
    assert "result" not in final, "a cancelled run has no result to present"


async def test_without_a_stream_the_original_single_pass_is_unchanged():
    """No sink and no profile: enrichment happens before ranking, as it always did."""
    world = World()
    world.add("22", 1)
    intel = FakeIntel()

    result = await world.use_case(threat_intel=intel).execute("node")

    assert result.recommendations
    assert all(v.threat_intel_timestamp for v in result.recommendations[0].scan.vulnerabilities)


async def test_ndjson_end_to_end_is_valid_json_lines_and_nothing_else():
    world = World()
    world.add("22", 1)
    world.add("20", 0)
    out = io.StringIO()
    events = EventStream([NdjsonSink(out)], command="recommend", run_id="20260930T000000Z-cafebabe")

    await world.use_case(threat_intel=FakeIntel(), events=events).execute("node")

    lines = out.getvalue().splitlines()
    assert lines, "the stream produced nothing"
    parsed = [json.loads(line) for line in lines]  # every line, and only lines, are JSON
    assert parsed[0]["type"] == "run_started" and parsed[-1]["final"] is True
    assert "\x1b" not in out.getvalue(), "no ANSI on a structured stream"
    assert {p["run_id"] for p in parsed} == {"20260930T000000Z-cafebabe"}


async def test_limiting_intelligence_to_the_finalists_is_stated_not_hidden():
    world = World()
    for i in range(14):
        world.add(f"{30 + i}", 1)
    intel = FakeIntel()

    result = await world.use_case(threat_intel=intel, enrichment=Enrichment.FINALISTS).execute(
        "node"
    )

    # Ten finalists (2 x TOP_N) were enriched; the other four were not, and the
    # result says how that limits comparing them.
    assert "for 10 of 14" in result.enrichment_note
    assert "UNKNOWN" in result.enrichment_note
    assert intel.requests["kev"] == 10


async def test_secrets_in_a_scan_error_are_redacted_in_the_stream():
    from dockerls.domain.entities.scan_result import ScanResult, ScanStatus

    world = World()
    world.add("22", 0)
    world.add("20", 0)
    out = io.StringIO()
    events = EventStream([NdjsonSink(out)], command="recommend")

    async def leaking_scan(reference, platform=None):
        return ScanResult(
            image_reference=reference,
            scanner="trivy",
            scan_timestamp="2026-01-01T00:00:00Z",
            status=ScanStatus.ERROR,
            error_message=(
                "pull failed: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzIjoxfQ.sigsigsig "
                "token=hunter2secret"
            ),
        )

    world.scanner.scan = leaking_scan  # type: ignore[method-assign]
    await world.use_case(events=events).execute("node")

    assert "hunter2secret" not in out.getvalue()
    assert "eyJhbGci" not in out.getvalue()
    json.loads(out.getvalue().splitlines()[-1])  # and the final event is still valid JSON
