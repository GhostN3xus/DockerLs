from __future__ import annotations

import io
import sys

import pytest
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


class TestSingleLiveDisplay:
    """A duplicated progress bar means two live displays, or results drawn
    into the live region. Both are structurally excluded here."""

    def test_exactly_one_progress_instance_exists_in_the_package(self):
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parents[3] / "dockerls"
        hits = [
            str(p.relative_to(root))
            for p in root.rglob("*.py")
            for line in p.read_text().splitlines()
            if re.search(r"\bProgress\(|\bLive\(|console\.status\(", line)
        ]
        assert hits == ["cli/progress.py"], f"more than one live display: {hits}"

    def test_observer_is_not_reentrant(self):
        console, _ = _console()
        obs = RichScanObserver(console)
        # The nesting IS the subject under test -- it must not be collapsed.
        with obs:  # noqa: SIM117
            with pytest.raises(RuntimeError, match="not re-entrant"):
                with obs:
                    pass

    def test_only_one_task_across_every_phase(self):
        """Each phase renames the single task; it never adds another line."""
        console, _ = _console()
        with RichScanObserver(console) as obs:
            obs.phase("Preparing vulnerability database")
            obs.phase("Fetching tags for node")
            obs.start(3)
            for ref in ("node:a", "node:b", "node:c"):
                obs.scanning(ref)
                obs.finished(ref, True)
            obs.phase("Cross-validating top 3 candidates")
            obs.phase("Verifying tags on Docker Hub")
            assert len(obs.progress.tasks) == 1

    def test_progress_defaults_to_stderr(self):
        obs = RichScanObserver()
        assert obs._console.stderr is True

    def test_results_console_is_untouched_by_progress(self):
        """The results stream must carry no progress frames at all."""
        results = Console(file=io.StringIO(), force_terminal=True, width=100)
        with RichScanObserver() as obs:
            obs.start(2)
            obs.scanning("node:22-alpine")
            results.print("Recommended Images")
            obs.finished("node:22-alpine", True)
        out = results.file.getvalue()
        assert "Recommended Images" in out
        assert "Scanning" not in out
        assert "\x1b[2K" not in out

    def test_stray_writes_are_captured_during_the_live_region(self):
        console, _ = _console()
        with RichScanObserver(console) as obs:
            obs.start(1)
            # Rich swaps sys.stdout/sys.stderr while the display is live.
            assert sys.stdout is not obs._console.file
            assert type(sys.stdout).__name__ == "FileProxy"
            assert type(sys.stderr).__name__ == "FileProxy"
        assert type(sys.stdout).__name__ != "FileProxy"
