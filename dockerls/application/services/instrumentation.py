"""Where a run's time and requests went, stage by stage.

The pipeline knew how many scans it performed and discarded how long anything
took, so "why did that take four minutes" had no answer from the outside. This
collects wall-clock time per named stage, request counts per source and the
time until the first useful result, on the monotonic clock.

It is deliberately a plain accumulator: stages may overlap (discovery and the
database download run together), so the per-stage times do **not** sum to the
total, and the report says so rather than pretending they partition the run.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

#: Stage names, in the order a run usually meets them. Free-form names are
#: accepted too; these exist so producers and the docs agree on spelling.
STAGES = (
    "startup",
    "discovery",
    "database_preparation",
    "identity_resolution",
    "queue_wait",
    "scan_primary",
    "scan_secondary",
    "enrichment",
    "inspection",
    "cache",
    "rendering",
)


class RunInstrumentation:
    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._started = clock()
        self._seconds: dict[str, float] = defaultdict(float)
        self._calls: Counter[str] = Counter()
        self.requests: Counter[str] = Counter()
        self.counters: Counter[str] = Counter()
        self._first_result: float | None = None
        self._samples: dict[str, list[float]] = defaultdict(list)

    @contextmanager
    def stage(self, name: str) -> Iterator[None]:
        began = self._clock()
        try:
            yield
        finally:
            self.add(name, self._clock() - began)

    def add(self, name: str, seconds: float) -> None:
        self._seconds[name] += max(0.0, seconds)
        self._calls[name] += 1
        self._samples[name].append(max(0.0, seconds))

    def request(self, source: str, count: int = 1) -> None:
        self.requests[source] += count

    def count(self, name: str, amount: int = 1) -> None:
        self.counters[name] += amount

    def mark_first_result(self) -> None:
        """The first moment something useful could be shown. Idempotent."""
        if self._first_result is None:
            self._first_result = self._clock() - self._started

    @property
    def elapsed(self) -> float:
        return self._clock() - self._started

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_seconds": round(self.elapsed, 3),
            "time_to_first_result_seconds": (
                None if self._first_result is None else round(self._first_result, 3)
            ),
            "stages": {
                name: {"seconds": round(self._seconds[name], 3), "calls": self._calls[name]}
                for name in sorted(self._seconds)
            },
            "stages_overlap": True,
            "requests_by_source": dict(sorted(self.requests.items())),
            "counters": dict(sorted(self.counters.items())),
        }
