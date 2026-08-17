from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence


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

    def phase_result(self, title: str, facts: Sequence[tuple[str, str]]) -> None:
        """Report what a finished phase actually did.

        `phase()` says what is happening; this says what came of it -- how
        many tags were found, how many collapsed onto one digest, how many
        answers came from cache. The pipeline knew all of it and reported
        none of it, so a long run looked identical to a stalled one.

        Facts are ordered pairs rather than a mapping so the renderer can
        print them in a deliberate order without sorting them into one.
        """
        ...


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

    def phase_result(self, title: str, facts: Sequence[tuple[str, str]]) -> None:
        return None
