from __future__ import annotations

from typing import TYPE_CHECKING

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

if TYPE_CHECKING:
    from types import TracebackType

    from rich.console import Console


class RichScanObserver:
    """Renders scan progress as a single self-updating line.

    This is the only thing allowed to write to the terminal while scans are
    running -- loguru is file-only, and scanner stderr is captured -- so the
    progress display can never be corrupted by interleaved log output.
    """

    def __init__(self, console: Console, enabled: bool = True):
        self._console = console
        self._enabled = enabled
        self._progress: Progress | None = None
        self._task_id: int | None = None
        self._total = 0
        self._done = 0
        self._failed = 0

    @property
    def failed(self) -> int:
        return self._failed

    def __enter__(self) -> RichScanObserver:
        if self._enabled:
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=24),
                TimeElapsedColumn(),
                console=self._console,
                transient=True,
            )
            self._progress.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._progress is not None:
            self._progress.stop()
            self._progress = None

    def _describe(self, image_reference: str) -> str:
        return f"Scanning {image_reference}... [{self._done + 1}/{self._total}]"

    def phase(self, description: str) -> None:
        if self._progress is None:
            return
        if self._task_id is None:
            self._task_id = self._progress.add_task(description, total=None)
        else:
            self._progress.update(self._task_id, description=description)

    def start(self, total: int) -> None:
        self._total = total
        self._done = 0
        if self._progress is None:
            return
        if self._task_id is None:
            self._task_id = self._progress.add_task("Scanning...", total=total)
        else:
            self._progress.update(self._task_id, total=total, completed=0)

    def scanning(self, image_reference: str) -> None:
        if self._progress is None or self._task_id is None:
            return
        self._progress.update(self._task_id, description=self._describe(image_reference))

    def finished(self, image_reference: str, ok: bool) -> None:
        self._done += 1
        if not ok:
            self._failed += 1
        if self._progress is None or self._task_id is None:
            return
        self._progress.update(self._task_id, completed=self._done)
