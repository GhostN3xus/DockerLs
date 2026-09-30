"""A monotonic time budget shared by everything a run does.

`--time-budget` limits the *whole* command -- discovery, database
preparation, scans, retries, enrichment and the final checks -- so the budget
is one object handed down, not a timeout re-derived at each layer. Each
operation asks it two questions: "may I start?" (`allows`) and "how long may I
take?" (`cap`). The wall clock is never used: an NTP step or a suspended
laptop must not stretch or collapse a budget, so the clock is
`time.monotonic`.

A missing budget is a `Deadline` too (`Deadline.unbounded()`), so callers
never branch on `None`.
"""

from __future__ import annotations

import asyncio
import math
import time
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

T = TypeVar("T")


class DeadlineExceededError(TimeoutError):
    """The run's time budget ran out.

    A `TimeoutError` subclass so code that already treats a timeout as "not
    measured" keeps doing so, but distinguishable: an exhausted *budget* is
    not a scanner fault and must not trigger the fallback scanner.
    """


class Deadline:
    __slots__ = ("_clock", "_end", "_start", "total")

    def __init__(
        self, seconds: float | None, *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        if seconds is not None and (not math.isfinite(seconds) or seconds <= 0):
            raise ValueError("a time budget must be a positive number of seconds")
        self._clock = clock
        self._start = clock()
        self.total = seconds
        self._end = None if seconds is None else self._start + seconds

    @classmethod
    def unbounded(cls) -> Deadline:
        return cls(None)

    @property
    def bounded(self) -> bool:
        return self._end is not None

    def elapsed(self) -> float:
        return self._clock() - self._start

    def remaining(self) -> float:
        """Seconds left; `inf` when there is no budget."""
        if self._end is None:
            return math.inf
        return max(0.0, self._end - self._clock())

    @property
    def expired(self) -> bool:
        return self.bounded and self.remaining() <= 0.0

    def allows(self, needed: float) -> bool:
        """Whether an operation that needs at least `needed` seconds may start.

        Starting a scan with two seconds left would only produce a killed
        subprocess and a `TIMEOUT` that says nothing about the image; it is
        refused up front and reported as *not started*.
        """
        return self.remaining() >= needed

    def cap(self, seconds: float) -> float:
        """`seconds`, or what is left of the budget when that is smaller."""
        return min(seconds, self.remaining())


async def run_within(
    deadline: Deadline, operation: Callable[[], Awaitable[T]], *, cap: float | None = None
) -> T:
    """Run `operation`, cancelling it when the budget (or `cap`) runs out.

    Cancellation is what stops subprocesses: `run_capture` reaps its child in
    a `finally`, so cancelling the awaiting task terminates the scanner
    instead of leaving it running past the run.
    """
    limit = deadline.remaining() if cap is None else deadline.cap(cap)
    if limit <= 0:
        raise DeadlineExceededError("time budget exhausted")
    if math.isinf(limit):
        return await operation()
    try:
        return await asyncio.wait_for(operation(), timeout=limit)
    except TimeoutError as e:
        raise DeadlineExceededError("time budget exhausted while running") from e
