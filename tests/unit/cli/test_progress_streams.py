"""Progress is allowed to be rich; it is not allowed to reach stdout.

Two invocations must survive whatever the progress display does:

    dockerls recommend node > report.txt
    dockerls recommend node --format json | jq .

The first means results and progress cannot share a stream. The second
means the display is off entirely, because a spinner frame inside a JSON
document is not a JSON document.
"""

from __future__ import annotations

import io
import re

from rich.console import Console

from dockerls.application.dto.analysis import AnalysisResult, RunMetrics
from dockerls.application.services.progress import NullObserver, ScanObserver
from dockerls.cli.progress import RichScanObserver

_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")


def _visible(output: str) -> str:
    """Strip ANSI so assertions are about text, not terminal control."""
    return _ANSI.sub("", output)


def _observer(stream: io.StringIO, enabled: bool = True) -> RichScanObserver:
    # force_terminal keeps Rich emitting the live display into a StringIO,
    # which is what a real terminal would receive.
    console = Console(file=stream, force_terminal=True, width=100)
    return RichScanObserver(console=console, enabled=enabled)


class TestBothObserversSatisfyTheProtocol:
    def test_null_observer_is_a_scan_observer(self):
        assert isinstance(NullObserver(), ScanObserver)

    def test_rich_observer_is_a_scan_observer(self):
        assert isinstance(RichScanObserver(enabled=False), ScanObserver)

    def test_null_observer_accepts_every_event(self):
        """It stands in wherever nothing is watching, so a missing method
        would be an AttributeError in the middle of a scan."""
        observer = NullObserver()
        observer.phase("x")
        observer.phase_result("x", [("a", "1")])
        observer.start(3)
        observer.scanning("node:22")
        observer.finished("node:22", ok=True)


class TestPhaseResultRendering:
    def test_facts_are_rendered_as_a_tree(self):
        stream = io.StringIO()
        with _observer(stream) as observer:
            observer.phase_result("Discovered tags", [("found", "100"), ("sources", "Docker Hub")])

        output = stream.getvalue()
        assert "Discovered tags" in output
        assert "found" in output and "100" in output
        assert "├─" in output
        assert "└─" in output

    def test_the_last_fact_closes_the_tree(self):
        stream = io.StringIO()
        with _observer(stream) as observer:
            observer.phase_result("T", [("a", "1"), ("b", "2"), ("c", "3")])

        output = stream.getvalue()
        assert output.count("├─") == 2
        assert output.count("└─") == 1

    def test_a_single_fact_uses_only_the_closing_branch(self):
        stream = io.StringIO()
        with _observer(stream) as observer:
            observer.phase_result("T", [("only", "1")])

        output = stream.getvalue()
        assert "├─" not in output
        assert "└─" in output

    def test_no_facts_prints_nothing(self):
        """An empty phase must not leave a bare heading behind. Only the
        live display's own cursor control sequences may appear."""
        stream = io.StringIO()
        with _observer(stream) as observer:
            observer.phase_result("Empty", [])
        assert "Empty" not in _visible(stream.getvalue())

    def test_nothing_is_printed_when_the_display_is_disabled(self):
        """`--no-progress` and `--format json` both land here."""
        stream = io.StringIO()
        with _observer(stream, enabled=False) as observer:
            observer.phase_result("Discovered tags", [("found", "100")])
            observer.phase("Scanning")
            observer.start(10)
            observer.scanning("node:22")
            observer.finished("node:22", ok=True)
        assert stream.getvalue() == ""


class TestProgressNeverTouchesStdout:
    def test_the_default_console_writes_to_stderr(self):
        """The split is what makes `dockerls recommend > out.txt` produce a
        file of results with no progress frames in it."""
        observer = RichScanObserver(enabled=False)
        assert observer._console.stderr is True

    def test_events_outside_a_context_are_ignored(self):
        """Nothing may be drawn before `__enter__` or after `__exit__`;
        that is where a stray frame would land in the results stream."""
        stream = io.StringIO()
        observer = _observer(stream)
        observer.phase("before")
        observer.phase_result("before", [("a", "1")])
        observer.finished("node:22", ok=True)
        assert stream.getvalue() == ""

        with observer:
            pass
        observer.phase_result("after", [("a", "1")])
        after = stream.getvalue()
        assert "after" not in after


class TestRunMetrics:
    def test_duplicates_are_the_gap_between_tags_and_digests(self):
        metrics = RunMetrics(tags_discovered=100, unique_digests=84)
        assert metrics.duplicates_collapsed == 16

    def test_duplicates_never_go_negative(self):
        """A source that reports no digests leaves `unique_digests` at 0;
        that is missing data, not 100 duplicates removed."""
        metrics = RunMetrics(tags_discovered=0, unique_digests=5)
        assert metrics.duplicates_collapsed == 0

    def test_hit_rate_is_over_everything_considered(self):
        metrics = RunMetrics(cache_hits=3, scans_performed=1)
        assert metrics.cache_hit_rate == 0.75

    def test_hit_rate_of_an_empty_run_is_zero_not_an_error(self):
        assert RunMetrics().cache_hit_rate == 0.0

    def test_metrics_are_serialised_for_json_consumers(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=3,
            baseline_met=False,
            metrics=RunMetrics(tags_discovered=3, unique_digests=2, scans_performed=2, workers=10),
        )
        payload = result.model_dump()
        assert payload["metrics"]["scans_performed"] == 2
        assert payload["metrics"]["unique_digests"] == 2

    def test_a_result_without_metrics_still_serialises(self):
        """Backwards compatibility: every existing construction site omits
        `metrics`, and none of them may start failing."""
        payload = AnalysisResult(
            query="node", total_tags_scanned=0, baseline_met=False
        ).model_dump()
        assert payload["metrics"]["tags_discovered"] == 0
