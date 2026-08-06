from __future__ import annotations

import asyncio
import json
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dockerls.cli.dependencies import (
    build_recommend_use_case,
    enable_console_logging,
    resolve_tag_limit,
)
from dockerls.cli.progress import RichScanObserver
from dockerls.infrastructure.evidence import slugify_reference

if TYPE_CHECKING:
    from collections.abc import Callable

    from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis

console = Console()

# Exit codes, in order of severity:
#   0 = an image meeting the baseline (Critical=0, High=0, Medium<=max) was found
#   1 = a hard error occurred (nothing could be scanned, or --fail-on was violated)
#   2 = no baseline image, but fallback alternatives were found
#   3 = nothing usable was found at all
EXIT_BASELINE_MET = 0
EXIT_ERROR = 1
EXIT_ALTERNATIVES_FOUND = 2
EXIT_NONE_FOUND = 3

DISPUTED_SCORE_LABEL = "[yellow]!disputed[/yellow]"


class FailOn(StrEnum):
    NONE = "none"
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


_FAIL_ON_COUNT: dict[FailOn, Callable[[ImageAnalysis], int]] = {
    FailOn.CRITICAL: lambda a: a.scan.critical_count,
    FailOn.HIGH: lambda a: a.scan.critical_count + a.scan.high_count,
    FailOn.MEDIUM: lambda a: a.scan.critical_count + a.scan.high_count + a.scan.medium_count,
}


def recommend(
    image: str = typer.Argument(help="Docker image name (e.g., node, python, nginx)"),
    max_critical: int | None = typer.Option(
        None, "--max-critical", help="Max critical vulns allowed [config: max_critical, default 0]"
    ),
    max_high: int | None = typer.Option(
        None, "--max-high", help="Max high vulns allowed [config: max_high, default 0]"
    ),
    max_medium: int | None = typer.Option(
        None, "--max-medium", help="Max medium vulns allowed [config: max_medium, default 5]"
    ),
    limit: int | None = typer.Option(
        None, "--limit", "-l", help="Max tags to scan [config: max_tags, default 100]"
    ),
    workers: int | None = typer.Option(
        None, "--workers", "-w", help="Concurrent workers [config: workers, default 10]"
    ),
    fail_on: FailOn = typer.Option(
        FailOn.NONE, "--fail-on", help="Exit non-zero if the top result has vulns at/above severity"
    ),
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table or json"
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
    no_progress: bool = typer.Option(False, "--no-progress", help="Disable the progress display"),
    no_cross_validate: bool = typer.Option(
        False, "--no-cross-validate", help="Skip second-scanner validation of top candidates"
    ),
    no_hub_check: bool = typer.Option(
        False, "--no-hub-check", help="Skip registry tag existence verification"
    ),
    no_hardened: bool = typer.Option(
        False, "--no-hardened", help="Search Docker Hub only (skip Chainguard/Distroless)"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Also print logs to stderr (they always go to the log file)"
    ),
) -> None:
    """Recommend the most secure Docker image tags."""
    if no_color:
        console.no_color = True
    if verbose:
        enable_console_logging()
    try:
        asyncio.run(
            _recommend(
                image,
                max_critical,
                max_high,
                max_medium,
                limit,
                workers,
                fail_on,
                output_format,
                show_progress=not no_progress and output_format != "json",
                cross_validate=not no_cross_validate,
                verify_hub_tags=not no_hub_check,
                include_hardened=not no_hardened,
            )
        )
    except ValueError as e:
        # Bad thresholds are user error, not a crash: show the message, not
        # a stack trace (pretty_exceptions_enable is off app-wide).
        console.print(f"[red]Invalid configuration:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e


async def _recommend(
    image: str,
    max_critical: int | None,
    max_high: int | None,
    max_medium: int | None,
    limit: int | None,
    workers: int | None,
    fail_on: FailOn,
    output_format: str,
    show_progress: bool = True,
    cross_validate: bool = True,
    verify_hub_tags: bool = True,
    include_hardened: bool = True,
) -> None:
    # The observer builds its own stderr console; `console` (stdout) is left
    # exclusively for results so the two streams cannot interleave.
    with RichScanObserver(enabled=show_progress) as observer:
        use_case = await build_recommend_use_case(
            max_critical=max_critical,
            max_high=max_high,
            max_medium=max_medium,
            workers=workers,
            observer=observer,
            cross_validate=cross_validate,
            verify_hub_tags=verify_hub_tags,
            include_hardened=include_hardened,
        )
        result = await use_case.execute(image, limit=resolve_tag_limit(limit))

    if output_format == "json":
        console.print(json.dumps(result.model_dump(), indent=2, default=str), soft_wrap=True)
        raise typer.Exit(_exit_code(result, fail_on))

    _print_summary(result)

    if result.baseline_met and result.recommendations:
        console.print(Panel("[bold green]Recommended Images[/bold green]", expand=False))
        _print_table(result.recommendations)
        _print_details(result.recommendations)
        _print_divergences(result.recommendations)
    elif result.alternatives:
        console.print(Panel(_baseline_miss_message(result), expand=False))
        _print_table(result.alternatives)
        _print_details(result.alternatives)
        _print_divergences(result.alternatives)
    else:
        console.print("[red]No suitable images found.[/red]")
        console.print(f"[dim]{_baseline_line(result)}[/dim]")

    _print_tier_warnings(result.recommendations or result.alternatives)
    _print_unverified(result)

    if result.evidence_manifest:
        console.print(f"\n[dim]Evidence manifest: {result.evidence_manifest}[/dim]")

    raise typer.Exit(_exit_code(result, fail_on))


def _baseline_line(result: AnalysisResult) -> str:
    if result.baseline is None:
        return ""
    return f"Baseline: {result.baseline.describe()}."


def _baseline_miss_message(result: AnalysisResult) -> str:
    """Name the exact threshold that was not met, so "no match" is a fact
    the reader can check rather than an opaque verdict."""
    baseline = _baseline_line(result)
    detail = f"{baseline}\n" if baseline else ""
    return (
        f"[bold yellow]No image found matching baseline.[/bold yellow]\n"
        f"[yellow]{detail}"
        f"No image met it -- showing the closest alternatives.[/yellow]"
    )


def _print_summary(result: AnalysisResult) -> None:
    """One-line account of the run, so a clean table can never hide the
    fact that half the candidates failed to scan."""
    analyzed = result.total_tags_analyzed
    total = result.total_tags_scanned
    skipped = result.unverified_count

    parts = [f"[green]OK {analyzed}/{total} analyzed[/green]"]
    if skipped:
        parts.append(f"[yellow]X {skipped} skipped (technical error)[/yellow]")
    if result.sources_searched:
        parts.append(f"[magenta]sources: {', '.join(result.sources_searched)}[/magenta]")
    console.print(" | ".join(parts))
    if result.log_file:
        # Its own line: a wrapped path is a path the user cannot copy.
        console.print(f"[dim]log: {result.log_file}[/dim]", soft_wrap=True)
    console.print()


def _hub_status(analysis: ImageAnalysis) -> str:
    if analysis.hub_tag_verified is True:
        return "[green]OK[/green]"
    if analysis.hub_tag_verified is False:
        return "[red]missing[/red]"
    return "[dim]n/a[/dim]"


def _print_table(analyses: list[ImageAnalysis]) -> None:
    # Kept deliberately narrow so it survives an 80-column terminal without
    # ellipsizing the image reference -- the one cell the reader must be
    # able to copy verbatim. Severity counts collapse into a single
    # Critical/High/Medium cell, and full Hub URLs are listed below.
    table = Table()
    table.add_column("#", justify="right", style="dim")
    table.add_column("Image", style="cyan bold", overflow="fold")
    table.add_column("Source", style="magenta")
    table.add_column("Score", justify="right", style="green", no_wrap=True)
    table.add_column("Tier", justify="center")
    table.add_column("C/H/M", justify="center", no_wrap=True)
    table.add_column("Fix", justify="right", style="green")
    table.add_column("Rem", justify="right")
    table.add_column("Tag", justify="center")

    styles = {"S": "bold green", "A": "bold blue", "B": "bold yellow", "C": "bold red"}
    for i, a in enumerate(analyses, 1):
        ts = styles.get(a.tier, "")
        # A score two scanners disagree about is not shown as a number:
        # displaying it would imply a confidence the data does not support.
        score = DISPUTED_SCORE_LABEL if a.scan_divergence else str(a.security_score)
        crit_style = "red" if a.scan.critical_count else "dim"
        counts = (
            f"[{crit_style}]{a.scan.critical_count}[/{crit_style}]/"
            f"[yellow]{a.scan.high_count}[/yellow]/{a.scan.medium_count}"
        )
        table.add_row(
            str(i),
            a.image.full_reference,
            a.image.source,
            score,
            f"[{ts}]{a.tier}[/{ts}]" if ts else a.tier,
            counts,
            str(a.scan.fixable_count),
            f"{a.remediation_score}%",
            _hub_status(a),
        )
    console.print(table)
    console.print(
        "[dim]C/H/M = Critical/High/Medium | Fix = fixable | Rem = remediation | "
        "Tag = confirmed in source registry[/dim]"
    )


def _print_details(analyses: list[ImageAnalysis]) -> None:
    """Per-image registry link and the scan evidence backing its score.

    Both are listed below the table rather than in it: URLs and file paths
    are far too wide for a terminal column, and each image needs its *own*
    evidence path, not just a pointer to the aggregate manifest.
    """
    if not analyses:
        return
    console.print("\n[bold]Details[/bold]")
    for i, a in enumerate(analyses, 1):
        console.print(f"  {i}. [cyan]{a.image.full_reference}[/cyan]  [dim]{a.image.source}[/dim]")
        if a.hub_url:
            # soft_wrap keeps the URL on one line so it stays copy-pasteable.
            console.print(f"     link:     [link={a.hub_url}]{a.hub_url}[/link]", soft_wrap=True)
        if a.evidence_paths:
            for scanner, path in sorted(a.evidence_paths.items()):
                note = _shared_scan_note(a, path)
                console.print(f"     {scanner + ':':9} [dim]{path}{note}[/dim]", soft_wrap=True)
        else:
            console.print("     [dim]evidence: not recorded[/dim]")


def _shared_scan_note(analysis: ImageAnalysis, path: str) -> str:
    """Flag evidence produced under a sibling tag's name.

    Tags that share a manifest digest are scanned once and share the
    result, so the file can be named for whichever tag triggered the scan.
    That is correct -- they are the same image -- but without saying so the
    path looks like it belongs to the wrong image.
    """
    if not path:
        return ""
    own_prefix = f"{slugify_reference(analysis.image.full_reference)}__"
    return "" if Path(path).name.startswith(own_prefix) else "  (shared digest)"


# Tier meanings that the reader must act on. Tier C never reaches the table
# (it fails the baseline and the alternatives filter), but Tier B can, and
# the README calling it "conditional" is no use to someone reading a
# terminal.
_TIER_WARNINGS = {
    "B": "conditional -- requires human review before production use",
    "C": "not production ready",
}


def _print_tier_warnings(analyses: list[ImageAnalysis]) -> None:
    flagged = [a for a in analyses if a.tier in _TIER_WARNINGS]
    if not flagged:
        return
    console.print("\n[bold yellow]! Requires review[/bold yellow]")
    for a in flagged:
        console.print(
            f"  {a.image.full_reference}  [dim]Tier {a.tier}: {_TIER_WARNINGS[a.tier]}[/dim]"
        )


def _print_divergences(analyses: list[ImageAnalysis]) -> None:
    disputed = [a for a in analyses if a.scan_divergence]
    if not disputed:
        return
    console.print("\n[bold yellow]! Scanner divergence[/bold yellow]")
    for a in disputed:
        console.print(f"  {a.image.full_reference}: [dim]{a.scan_divergence}[/dim]")


REASON_MAX_LEN = 90


def _short_reason(reason: str) -> str:
    """Collapse a multi-line scanner stderr dump into one readable line.

    The untruncated text is in the log file and in `--format json`; the
    terminal only needs enough to tell failures apart.
    """
    collapsed = " ".join(reason.split())
    if len(collapsed) <= REASON_MAX_LEN:
        return collapsed
    return collapsed[: REASON_MAX_LEN - 3] + "..."


def _print_unverified(result: AnalysisResult) -> None:
    if not result.unverified:
        return
    console.print("\n[bold yellow]! Unverified (technical error)[/bold yellow]")
    console.print(
        "[dim]  These tags were never scored -- no successful scan, no recommendation.[/dim]"
    )
    for item in result.unverified[:10]:
        console.print(
            f"  {item.image_reference}  [dim]{item.status}: {_short_reason(item.reason)}[/dim]"
        )
    remaining = len(result.unverified) - 10
    if remaining > 0:
        console.print(f"  [dim]... and {remaining} more (see log file)[/dim]")


def _exit_code(result: AnalysisResult, fail_on: FailOn) -> int:
    items = result.recommendations or result.alternatives
    if items and fail_on != FailOn.NONE:
        counter = _FAIL_ON_COUNT[fail_on]
        if counter(items[0]) > 0:
            return EXIT_ERROR

    if result.baseline_met and result.recommendations:
        return EXIT_BASELINE_MET
    if result.alternatives:
        return EXIT_ALTERNATIVES_FOUND
    if result.total_tags_scanned == 0:
        return EXIT_ERROR
    return EXIT_NONE_FOUND
