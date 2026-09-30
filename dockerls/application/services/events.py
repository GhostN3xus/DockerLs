"""Progressive results, for a terminal and for automation.

A recommendation used to arrive as one block after the last scan. Nothing
could be shown -- or acted on -- while two minutes of scanning went by, and a
run that was cut short produced nothing at all.

The event stream fixes that without lying about what it shows. Three rules
are enforced by `EventStream` itself, not left to each emitter:

* **Provisional is not final.** Every event says which it is. A ranking built
  before threat intelligence or the final checks arrived is
  `provisional: true`, carries the checks still `pending`, and can be
  *revised* by a later event. Exactly one event is `final`, it is the last,
  and it states the run's completeness (`COMPLETE`, `PARTIAL`, ...) -- an
  interrupted run never ends in something that reads like a finished audit.
* **Structured output stays clean.** Sinks write only serialised events. No
  log line, progress bar or ANSI sequence ever enters the stream; those go to
  stderr and the log file.
* **Nothing sensitive leaves.** Every string value is passed through the
  project's redactor before it is serialised, the same one the logs and the
  evidence store use.

The wire format is NDJSON: one JSON object per line, `schema` versioned so a
consumer can refuse what it does not understand.
"""

from __future__ import annotations

import json
import time
from typing import IO, TYPE_CHECKING, Any, Protocol

from dockerls.infrastructure.redaction import redact_values

if TYPE_CHECKING:
    from collections.abc import Callable

#: Bump on any change to the meaning of a field.
EVENT_SCHEMA = "dockerls.events/1"

#: Event types, for producers and the docs to agree on spelling.
RUN_STARTED = "run_started"
PHASE = "phase"
CANDIDATE_MEASURED = "candidate_measured"
RANKING = "ranking"
RANKING_REVISED = "ranking_revised"
CHECK = "check"
RUN_FINISHED = "run_finished"


class EventSink(Protocol):
    def write(self, event: dict[str, Any]) -> None: ...


class NdjsonSink:
    """One JSON object per line, flushed, on a stream that carries nothing else."""

    def __init__(self, stream: IO[str]) -> None:
        self._stream = stream
        self._broken = False

    def write(self, event: dict[str, Any]) -> None:
        if self._broken:
            return
        line = json.dumps(redact_values(event), ensure_ascii=False, default=str, allow_nan=False)
        try:
            self._stream.write(line + "\n")
            self._stream.flush()
        except BrokenPipeError:
            # The consumer went away (`| head`); stop writing, keep measuring.
            self._broken = True


class ListSink:
    """Collects events in memory."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def write(self, event: dict[str, Any]) -> None:
        self.events.append(event)


class EventStream:
    """Numbers, times and validates events before handing them to sinks."""

    def __init__(
        self,
        sinks: list[EventSink] | None = None,
        *,
        command: str = "",
        run_id: str = "",
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._sinks = list(sinks or [])
        self._command = command
        self._run_id = run_id
        self._clock = clock
        self._started = clock()
        self._seq = 0
        self._finished = False
        self._revision = 0

    @property
    def enabled(self) -> bool:
        return bool(self._sinks)

    @property
    def finished(self) -> bool:
        return self._finished

    def next_revision(self) -> int:
        """Ranking revisions count up from 1; a consumer keeps the highest."""
        self._revision += 1
        return self._revision

    def emit(
        self,
        event_type: str,
        *,
        provisional: bool = False,
        final: bool = False,
        pending: list[str] | None = None,
        **data: Any,
    ) -> None:
        if not self._sinks:
            return
        if self._finished:
            raise RuntimeError(f"event {event_type!r} emitted after the final event")
        if final and provisional:
            raise ValueError("an event cannot be both provisional and final")
        self._seq += 1
        event: dict[str, Any] = {
            "schema": EVENT_SCHEMA,
            "seq": self._seq,
            "type": event_type,
            "command": self._command,
            "run_id": self._run_id,
            "elapsed_seconds": round(self._clock() - self._started, 3),
            "provisional": provisional,
            "final": final,
            "pending_checks": list(pending or []),
            **data,
        }
        if final:
            self._finished = True
        for sink in self._sinks:
            sink.write(event)
