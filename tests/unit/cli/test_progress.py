from __future__ import annotations

import io

from rich.console import Console

from dockerls.application.services.progress import NullObserver, ScanObserver
from dockerls.cli.progress import RichScanObserver


def _console() -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    return Console(file=buf, force_terminal=True, width=100), buf


class TestRichScanObserver:
    def test_satisfies_the_observer_protocol(self):
        console, _ = _console()
        assert isinstance(RichScanObserver(console), ScanObserver)
        assert isinstance(NullObserver(), ScanObserver)

    def test_description_shows_image_and_position(self):
        console, _ = _console()
        obs = RichScanObserver(console)
        obs.start(24)
        assert obs._describe("node:26.7-slim") == "Scanning node:26.7-slim... [1/24]"
        obs.finished("node:26.7-slim", True)
        obs.finished("node:22-alpine", True)
        assert obs._describe("node:20-alpine") == "Scanning node:20-alpine... [3/24]"

    def test_counts_failures(self):
        console, _ = _console()
        obs = RichScanObserver(console)
        obs.start(3)
        obs.finished("a", True)
        obs.finished("b", False)
        obs.finished("c", False)
        assert obs.failed == 2

    def test_disabled_observer_writes_nothing(self):
        console, buf = _console()
        with RichScanObserver(console, enabled=False) as obs:
            obs.phase("Preparing vulnerability database")
            obs.start(2)
            obs.scanning("node:22-alpine")
            obs.finished("node:22-alpine", True)
        assert buf.getvalue() == ""

    def test_progress_display_erases_itself_on_exit(self):
        """The bar must clear itself so it never sits above the table.

        The buffer still holds the frames that were drawn; what matters is
        that leaving the context emits the erase-line sequence, so the
        terminal is clean before the results are printed.
        """
        console, buf = _console()
        with RichScanObserver(console) as obs:
            obs.start(2)
            obs.scanning("node:22-alpine")
            obs.finished("node:22-alpine", True)
        out = buf.getvalue()
        assert "Scanning node:22-alpine... [1/2]" in out
        assert out.endswith("\x1b[1A\x1b[2K")

    def test_events_before_start_do_not_raise(self):
        console, _ = _console()
        with RichScanObserver(console) as obs:
            obs.scanning("node:22-alpine")
            obs.phase("Fetching tags for node")
            obs.start(1)
            obs.finished("node:22-alpine", True)

    def test_usable_outside_a_context_manager(self):
        # The use case may be built with an observer that was never entered
        # (e.g. --format json); every method must still be a safe no-op.
        console, buf = _console()
        obs = RichScanObserver(console)
        obs.phase("Preparing vulnerability database")
        obs.start(1)
        obs.scanning("node:22-alpine")
        obs.finished("node:22-alpine", True)
        assert buf.getvalue() == ""


class TestNullObserver:
    def test_all_methods_are_no_ops(self):
        obs = NullObserver()
        assert obs.start(5) is None
        assert obs.scanning("node:22") is None
        assert obs.finished("node:22", True) is None
        assert obs.phase("anything") is None
