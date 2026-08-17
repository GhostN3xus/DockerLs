"""Client-side rate limiting and circuit breaking for external APIs.

Every provider DockerLs talks to has a budget: the GitHub REST API allows 60
requests an hour to an anonymous client, Docker Hub throttles pulls, and a
registry that is having a bad day answers 5xx to everything. Two failure
modes follow from that, and both are the caller's fault rather than the
API's:

* a burst that spends the whole budget in the first second of a run, so the
  rest of the run gets 403s that look like the data does not exist;
* a retry loop that keeps hammering an endpoint which is already failing,
  turning a slow dependency into a hung command.

The token bucket addresses the first: requests are paced, and a caller that
asks faster than the budget allows waits rather than being refused. The
circuit breaker addresses the second: after a run of consecutive failures
the breaker opens and calls fail *immediately* for a cooldown, so an
unreachable provider costs one timeout instead of one per candidate. It
closes again after a single successful probe.

Neither ever turns a failure into a success. An open breaker raises, and the
caller reports the source as unavailable -- which is the honest outcome, and
the one the rest of this codebase is built to represent.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field

#: Jitter applied to the wait a caller computes, as a fraction of that wait.
#: Without it, N workers that all hit the limit at once wake up at the same
#: instant and collide again -- a thundering herd of their own making.
JITTER_FRACTION = 0.1


class RateLimiter:
    """Token bucket: at most `rate` operations per `period` seconds, on average.

    Bursts up to `burst` are allowed, because the common shape here is a
    handful of parallel lookups followed by a long quiet stretch, and pacing
    those to a strict interval would only add latency for no protection.
    """

    def __init__(self, rate: int, period: float = 1.0, burst: int | None = None):
        if rate < 1:
            raise ValueError("rate must be at least 1")
        if period <= 0:
            raise ValueError("period must be positive")
        self._rate = rate
        self._period = period
        self._capacity = float(burst if burst is not None else rate)
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a token is available, then consume it."""
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(
                    self._capacity, self._tokens + elapsed * (self._rate / self._period)
                )
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = 1.0 - self._tokens
                wait = deficit * (self._period / self._rate)
            # Slept outside the lock so waiting callers do not serialize on
            # each other's sleeps.
            await asyncio.sleep(wait * (1.0 + random.random() * JITTER_FRACTION))  # noqa: S311


class CircuitOpenError(RuntimeError):
    """The breaker is open: the provider is failing and is not being called."""


@dataclass
class CircuitBreaker:
    """Stop calling a provider that is consistently failing.

    State is intentionally minimal -- consecutive failures and the time the
    breaker opened. There is no half-open request accounting: the first call
    after the cooldown is the probe, and its outcome decides whether the
    breaker closes or re-opens.
    """

    #: Consecutive failures that trip the breaker.
    threshold: int = 5
    #: Seconds the breaker stays open before allowing a probe.
    cooldown: float = 60.0
    _failures: int = field(default=0, init=False)
    _opened_at: float = field(default=0.0, init=False)

    @property
    def is_open(self) -> bool:
        if self._failures < self.threshold:
            return False
        return (time.monotonic() - self._opened_at) < self.cooldown

    def check(self, provider: str) -> None:
        """Raise `CircuitOpenError` when the provider is being skipped."""
        if self.is_open:
            remaining = self.cooldown - (time.monotonic() - self._opened_at)
            raise CircuitOpenError(
                f"{provider} is unavailable after {self._failures} consecutive "
                f"failures; retrying in {max(0.0, remaining):.0f}s"
            )

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = 0.0

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self.threshold:
            # Re-stamped on every failure past the threshold so a provider
            # that keeps failing keeps the breaker open, rather than
            # re-opening the floodgates one cooldown after the first trip.
            self._opened_at = time.monotonic()
