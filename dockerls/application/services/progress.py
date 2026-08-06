from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ScanObserver(Protocol):
    """Reports scan progress to whatever owns the terminal.

    The use case must not print: it emits events, and the CLI decides how
    (or whether) to render them. This is what lets the terminal show a
    single clean progress line while every diagnostic goes to the log file.
    """

    def start(self, total: int) -> None: ...

    def scanning(self, image_reference: str) -> None: ...

    def finished(self, image_reference: str, ok: bool) -> None: ...

    def phase(self, description: str) -> None: ...


class NullObserver:
    """No-op observer used when nothing is watching (JSON output, tests)."""

    def start(self, total: int) -> None:
        return None

    def scanning(self, image_reference: str) -> None:
        return None

    def finished(self, image_reference: str, ok: bool) -> None:
        return None

    def phase(self, description: str) -> None:
        return None
