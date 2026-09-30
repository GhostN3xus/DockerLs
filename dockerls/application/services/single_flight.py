"""Share one in-flight computation between callers that ask the same question.

`recommend` used to guard each digest with a per-key lock, and `compare` had
nothing at all: two references that resolve to the same manifest -- or the
same reference twice -- each ran their own scanner process. A single-flight
table makes the second caller wait for the first one's result instead.

Semantics that matter here:

* The work runs in its own task, so one waiter being cancelled does not
  cancel the work the others still need; the task is cancelled only when the
  *last* waiter leaves (so a run-wide cancellation still stops the scanner).
* An exception is delivered to every waiter -- nobody silently retries the
  failing computation N times.
* The table is emptied when the work finishes: this coalesces concurrent
  callers, it is not a cache.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Hashable

T = TypeVar("T")


class _Flight(Generic[T]):
    __slots__ = ("task", "waiters")

    def __init__(self, task: asyncio.Task[T]) -> None:
        self.task = task
        self.waiters = 0


class SingleFlight(Generic[T]):
    def __init__(self) -> None:
        self._flights: dict[Hashable, _Flight[T]] = {}

    def in_flight(self) -> int:
        return len(self._flights)

    async def run(self, key: Hashable, factory: Callable[[], Awaitable[T]]) -> tuple[T, bool]:
        """`(result, shared)`; `shared` is True when this caller joined work
        another caller had already started."""
        flight = self._flights.get(key)
        shared = flight is not None
        if flight is None:
            task = asyncio.ensure_future(factory())
            flight = _Flight(task)
            self._flights[key] = flight
            task.add_done_callback(functools.partial(self._on_done, key, flight))
        flight.waiters += 1
        try:
            return await asyncio.shield(flight.task), shared
        finally:
            flight.waiters -= 1
            if flight.waiters == 0 and not flight.task.done():
                # The last caller left without a result (cancelled): nobody
                # needs the work any more, so stop it -- this is what ends the
                # scanner subprocess on a run-wide cancellation.
                flight.task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await flight.task

    def _on_done(self, key: Hashable, flight: _Flight[T], _task: asyncio.Task[T]) -> None:
        self._forget(key, flight)

    def _forget(self, key: Hashable, flight: _Flight[T]) -> None:
        if self._flights.get(key) is flight:
            del self._flights[key]
        # Retrieve the exception so an abandoned failing task does not log
        # "exception was never retrieved" -- waiters already received it.
        if not flight.task.cancelled():
            flight.task.exception()
