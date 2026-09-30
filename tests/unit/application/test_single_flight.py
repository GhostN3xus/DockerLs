"""Concurrent callers asking the same question share one computation."""

from __future__ import annotations

import asyncio

import pytest

from dockerls.application.services.single_flight import SingleFlight


async def test_concurrent_callers_share_one_run():
    flight: SingleFlight[int] = SingleFlight()
    calls = 0

    async def work() -> int:
        nonlocal calls
        calls += 1
        await asyncio.sleep(0.05)
        return 42

    results = await asyncio.gather(*(flight.run("k", work) for _ in range(5)))

    assert calls == 1
    assert [value for value, _ in results] == [42] * 5
    assert sorted(shared for _, shared in results) == [False, True, True, True, True]


async def test_different_keys_do_not_share():
    flight: SingleFlight[str] = SingleFlight()

    async def work(name: str) -> str:
        await asyncio.sleep(0.01)
        return name

    a, b = await asyncio.gather(
        flight.run("a", lambda: work("a")), flight.run("b", lambda: work("b"))
    )
    assert (a[0], b[0]) == ("a", "b")


async def test_it_coalesces_but_does_not_cache():
    flight: SingleFlight[int] = SingleFlight()
    calls = 0

    async def work() -> int:
        nonlocal calls
        calls += 1
        return calls

    assert (await flight.run("k", work))[0] == 1
    assert (await flight.run("k", work))[0] == 2
    assert flight.in_flight() == 0


async def test_an_exception_reaches_every_waiter():
    flight: SingleFlight[int] = SingleFlight()

    async def boom() -> int:
        await asyncio.sleep(0.01)
        raise RuntimeError("scanner exploded")

    outcomes = await asyncio.gather(
        *(flight.run("k", boom) for _ in range(3)), return_exceptions=True
    )
    assert all(isinstance(o, RuntimeError) for o in outcomes)


async def test_one_waiter_cancelling_does_not_cancel_the_others():
    flight: SingleFlight[int] = SingleFlight()
    finished = asyncio.Event()

    async def work() -> int:
        await asyncio.sleep(0.1)
        finished.set()
        return 7

    first = asyncio.ensure_future(flight.run("k", work))
    second = asyncio.ensure_future(flight.run("k", work))
    await asyncio.sleep(0.01)
    first.cancel()
    assert (await second)[0] == 7
    assert finished.is_set()
    with pytest.raises(asyncio.CancelledError):
        await first


async def test_the_last_waiter_cancelling_stops_the_work():
    flight: SingleFlight[int] = SingleFlight()
    cancelled = asyncio.Event()

    async def work() -> int:
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return 1

    waiter = asyncio.ensure_future(flight.run("k", work))
    await asyncio.sleep(0.01)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert cancelled.is_set()
    assert flight.in_flight() == 0
