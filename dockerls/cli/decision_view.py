"""Render a `DecisionSummary` first, so the answer is not buried under the table.

Every value here comes from the summary; nothing is recomputed. Two habits
keep the block honest:

* an unknown is printed as `unknown`, never as `0`, `none` or a blank;
* the score never appears without its blockers next to it.

The wording is English, like the rest of the interface.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dockerls.application.services.decision_summary import Category, Kind, humanize_age
from dockerls.cli.text import safe

if TYPE_CHECKING:
    from rich.console import Console

    from dockerls.application.services.decision_summary import DecisionSummary

_KIND_STYLE = {
    Kind.RECOMMENDED: "bold green",
    Kind.BEST_MEASURED: "bold yellow",
    Kind.NONE: "bold red",
}

_CATEGORY_STYLE = {
    Category.POLICY: "red",
    Category.INCOMPLETE: "yellow",
    Category.INFRASTRUCTURE: "magenta",
}

_ORIGIN_LABEL = {
    "scan": "new scan in this run",
    "cache": "reused from an earlier measurement (cache)",
    "shared": "shared with another image measured in this run",
}


def _count(value: int | None) -> str:
    return "unknown" if value is None else str(value)


def render_decision(console: Console, summary: DecisionSummary) -> None:
    style = _KIND_STYLE[summary.kind]
    console.print(f"\n[{style}]{safe(summary.headline)}[/{style}]")
    if summary.kind is Kind.NONE:
        _render_problems(console, summary)
        console.print(f"  [bold]Next:[/bold] {safe(summary.next_action)}")
        return

    rows: list[tuple[str, str]] = [("Image", f"[cyan bold]{safe(summary.image)}[/cyan bold]")]
    if summary.pinned_reference:
        rows.append(("Immutable", safe(summary.pinned_reference)))
    else:
        rows.append(
            ("Immutable", f"[yellow]not confirmed[/yellow] -- {safe(summary.identity_note)}")
        )
    rows.append(("Platform", safe(summary.platform) or "unknown"))
    if summary.reason:
        rows.append(("Why", safe(summary.reason)))

    critical = (
        f"[red]{_count(summary.critical)}[/red]" if summary.critical else _count(summary.critical)
    )
    fixable = (
        "unknown" if summary.fixable is None else f"{summary.fixable} of {_count(summary.total)}"
    )
    rows.append(
        ("Findings", f"Critical {critical} | High {_count(summary.high)} | fixable {fixable}")
    )
    rows.append(("Score", _score_line(summary)))
    rows.append(("Confidence", _confidence_line(summary)))
    rows.append(("Measured", _freshness_line(summary)))
    rows.append(("Origin", _ORIGIN_LABEL.get(summary.origin, "unknown")))

    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        console.print(f"  [bold]{label:<{width}}[/bold]  {value}")
    _render_problems(console, summary)
    console.print(f"  [bold]Next:[/bold] {safe(summary.next_action)}")


def _score_line(summary: DecisionSummary) -> str:
    """The score, never alone: the blockers that qualify it come with it."""
    if summary.score_disputed:
        text = f"[yellow]!disputed[/yellow] (tier {safe(summary.tier)}; two scanners disagree)"
        if summary.blockers:
            return f"{text} -- [red]not production ready:[/red] {safe(', '.join(summary.blockers))}"
        return text
    if summary.score is None:
        return "unknown"
    text = f"{summary.score} (tier {safe(summary.tier)})"
    if summary.blockers:
        return f"{text} -- [red]not production ready:[/red] {safe(', '.join(summary.blockers))}"
    if summary.production_ready:
        return f"{text} -- passes the production-readiness policy"
    return f"{text} -- not evaluated as production ready"


def _confidence_line(summary: DecisionSummary) -> str:
    pending = summary.pending_checks
    text = summary.confidence
    if pending:
        return f"{text} -- pending: {safe('; '.join(pending))}"
    return f"{text} -- no pending checks"


def _ago(seconds: float | None) -> str:
    return "unknown" if seconds is None else f"{humanize_age(seconds)} ago"


def _freshness_line(summary: DecisionSummary) -> str:
    return (
        f"{_ago(summary.measurement_age_seconds)} | "
        f"vulnerability database built {_ago(summary.db_age_seconds)}"
    )


def _render_problems(console: Console, summary: DecisionSummary) -> None:
    if not summary.problems:
        return
    console.print("  [bold]Not established[/bold]")
    for problem in summary.problems:
        category, _, rest = problem.partition(": ")
        try:
            style = _CATEGORY_STYLE[Category(category)]
        except ValueError:
            style = "white"
        console.print(f"    [{style}]{category}[/{style}] {safe(rest)}")
