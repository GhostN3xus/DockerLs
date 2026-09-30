"""A global time budget: monotonic, propagated, never a fake audit.

What matters: the budget covers every phase, subordinate work is cancelled when
it ends, work that cannot fit is not started, what finished is returned with an
explicit PARTIAL status, and an interrupted run is never presented as complete.
"""

from __future__ import annotations

import asyncio

import pytest

from dockerls.domain.entities.scan_result import ScanErrorKind
from dockerls.domain.value_objects.scan_plan import DeferralReason
from dockerls.exit_codes import (
    EXIT_ERROR,
    EXIT_OK,
    EXIT_PARTIAL_RESULT,
    EXIT_POLICY,
    EXIT_TIME_BUDGET_EXHAUSTED,
    exit_code_for_completeness,
)
from dockerls.utils.deadline import Deadline
from tests.unit.application.recommend_harness import FakeIntel, Repo, World, stream


async def test_a_run_that_fits_its_budget_is_complete_and_unchanged():
    world = World()
    world.add("22", 0)
    world.add("20", 1)

    result = await world.use_case(deadline=Deadline(30)).execute("node")

    assert result.completeness == "COMPLETE"
    assert result.deferred == []
    assert result.time_budget_seconds == 30
    assert result.elapsed_seconds < 30


async def test_scans_the_budget_cannot_cover_are_not_measured_and_the_run_is_partial():
    world = World()
    for i in range(6):
        world.add(f"{20 + i}", 0)
    world.scanner.latency = 0.25
    # One scan at a time, ~0.25s each, 0.7s to spend: some finish, the rest cannot.
    use_case = world.use_case(deadline=Deadline(0.7), max_concurrency=1, min_scan_seconds=0.2)

    result = await use_case.execute("node")

    measured = result.total_tags_analyzed
    assert 0 < measured < 6
    assert result.completeness == "PARTIAL"
    reasons = {d.reason for d in result.deferred}
    assert reasons == {DeferralReason.TIME_BUDGET}
    assert measured + len(result.deferred) == 6, (
        "every tag is either measured or named as not measured"
    )
    assert result.unverified == [], "running out of time is not a scan failure"
    assert result.errors == []


async def test_a_partial_result_still_ranks_what_was_measured_and_says_it_is_partial():
    world = World()
    world.add("22", 0)
    world.add("20", 2)
    world.add("18", 3)
    world.scanner.latency = 0.3
    use_case = world.use_case(deadline=Deadline(0.5), max_concurrency=1, min_scan_seconds=0.25)

    result = await use_case.execute("node")

    top = (result.recommendations or result.alternatives)[0]
    assert top.image.full_reference in {"node:22", "node:20"}
    assert result.completeness == "PARTIAL"
    # ... and the pending list never reads as a clean bill of health.
    assert result.pending_checks


async def test_the_budget_cancels_a_scan_that_is_still_running():
    world = World()
    world.add("22", 0)
    world.scanner.latency = 60
    cancelled = asyncio.Event()
    original = world.scanner.scan

    async def watched(reference, platform=None):
        try:
            return await original(reference, platform=platform)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    world.scanner.scan = watched  # type: ignore[method-assign]
    started = asyncio.get_running_loop().time()

    result = await world.use_case(deadline=Deadline(0.6), min_scan_seconds=0.1).execute("node")

    assert cancelled.is_set(), "the task was left running past the budget"
    assert asyncio.get_running_loop().time() - started < 5
    assert result.completeness == "NO_RESULT"
    assert result.total_tags_analyzed == 0


async def test_nothing_starts_when_the_budget_is_already_too_short_for_a_scan():
    world = World()
    world.add("22", 0)

    result = await world.use_case(deadline=Deadline(0.5), min_scan_seconds=30).execute("node")

    assert world.scanner.calls == [], "a scan was started that could not have finished"
    assert result.completeness == "NO_RESULT"
    assert [d.reason for d in result.deferred] == [DeferralReason.TIME_BUDGET]


async def test_discovery_is_inside_the_budget_too():
    world = World()
    world.add("22", 0)
    repo = Repo(world.tags, slow=30)

    result = await world.use_case(deadline=Deadline(0.4), repo=repo).execute("node")

    assert result.completeness == "NO_RESULT"
    assert result.total_tags_scanned == 0
    assert any("discovery" in p for p in result.pending_checks)


async def test_enrichment_cut_by_the_budget_leaves_intelligence_unknown_and_pending():
    world = World()
    world.add("22", 1)

    class SlowIntel(FakeIntel):
        async def known_exploited(self, cve_ids):
            await asyncio.sleep(30)
            return set()

    result = await world.use_case(
        deadline=Deadline(1.0), threat_intel=SlowIntel(), min_scan_seconds=0.1
    ).execute("node")

    assert result.completeness == "PARTIAL"
    assert any("threat intelligence" in p for p in result.pending_checks)
    top = (result.recommendations or result.alternatives)[0]
    assert all(not v.kev_status.is_known for v in top.scan.vulnerabilities), (
        "an enrichment that never happened must stay UNKNOWN, never become 'not exploited'"
    )


async def test_the_final_event_of_an_interrupted_run_says_partial_not_complete():
    world = World()
    for i in range(4):
        world.add(f"{20 + i}", 0)
    world.scanner.latency = 0.3
    events, sink = stream()

    await world.use_case(
        deadline=Deadline(0.5), events=events, max_concurrency=1, min_scan_seconds=0.25
    ).execute("node")

    final = sink.events[-1]
    assert final["final"] and final["status"] == "PARTIAL"
    assert final["result"]["completeness"] == "PARTIAL"


class TestExitCodes:
    def test_a_complete_run_keeps_the_exit_code_it_would_have_had(self):
        for code in (0, 1, 2, 3):
            assert exit_code_for_completeness(code, "COMPLETE") == code

    def test_a_partial_run_never_exits_zero(self):
        assert exit_code_for_completeness(EXIT_OK, "PARTIAL") == EXIT_PARTIAL_RESULT == 5
        assert exit_code_for_completeness(2, "PARTIAL") == EXIT_PARTIAL_RESULT

    def test_nothing_measured_in_time_is_its_own_code(self):
        assert exit_code_for_completeness(3, "NO_RESULT") == EXIT_TIME_BUDGET_EXHAUSTED == 4

    def test_a_violation_already_proven_is_not_softened_by_being_partial(self):
        assert exit_code_for_completeness(EXIT_POLICY, "PARTIAL", violation=True) == EXIT_POLICY

    def test_an_operational_error_stays_an_error(self):
        assert exit_code_for_completeness(EXIT_ERROR, "PARTIAL") == EXIT_ERROR

    def test_the_new_codes_do_not_collide_with_any_existing_one(self):
        existing = {0, 1, 2, 3}
        assert EXIT_PARTIAL_RESULT not in existing
        assert EXIT_TIME_BUDGET_EXHAUSTED not in existing


@pytest.mark.parametrize("bad", [0, -3])
def test_a_non_positive_budget_is_refused(bad):
    with pytest.raises(ValueError, match="positive"):
        Deadline(bad)


def test_the_scan_error_kind_for_a_budget_is_not_a_scanner_fault():
    """The fallback scanner must not be asked to retry what the *clock* cut off."""
    assert not ScanErrorKind.DEADLINE_EXCEEDED.is_scanner_fault
    assert not ScanErrorKind.PLATFORM_UNAVAILABLE.is_scanner_fault
