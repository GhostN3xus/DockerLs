"""The monotonic time budget: a fake clock proves it never reads the wall clock."""

from __future__ import annotations

import asyncio

import pytest

from dockerls.utils.deadline import Deadline, DeadlineExceededError, run_within


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_remaining_shrinks_with_the_monotonic_clock():
    clock = FakeClock()
    deadline = Deadline(60, clock=clock)
    assert deadline.remaining() == 60
    clock.now += 45
    assert deadline.remaining() == 15
    assert not deadline.expired
    clock.now += 100
    assert deadline.remaining() == 0
    assert deadline.expired


def test_an_operation_is_not_started_when_the_rest_cannot_hold_it():
    clock = FakeClock()
    deadline = Deadline(10, clock=clock)
    clock.now += 7
    assert deadline.allows(3)
    assert not deadline.allows(3.5)


def test_cap_never_exceeds_what_is_left():
    clock = FakeClock()
    deadline = Deadline(10, clock=clock)
    clock.now += 8
    assert deadline.cap(300) == 2


def test_unbounded_never_expires():
    deadline = Deadline.unbounded()
    assert not deadline.bounded
    assert deadline.allows(10**9)
    assert not deadline.expired
    assert deadline.cap(300) == 300


@pytest.mark.parametrize("bad", [0, -1, float("inf"), float("nan")])
def test_a_budget_must_be_a_positive_finite_number(bad):
    with pytest.raises(ValueError, match="positive"):
        Deadline(bad)


async def test_run_within_cancels_the_operation_when_time_runs_out():
    cancelled = asyncio.Event()

    async def slow() -> None:
        try:
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    with pytest.raises(DeadlineExceededError):
        await run_within(Deadline(0.05), slow)
    assert cancelled.is_set()


async def test_run_within_returns_the_result_in_time():
    async def quick() -> int:
        return 5

    assert await run_within(Deadline(5), quick) == 5
    assert await run_within(Deadline.unbounded(), quick) == 5


def test_an_exhausted_budget_is_a_timeout_error_but_a_distinct_one():
    assert issubclass(DeadlineExceededError, TimeoutError)
