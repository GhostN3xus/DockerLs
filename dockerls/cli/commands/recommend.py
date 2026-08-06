from __future__ import annotations

import asyncio
import json
from enum import Enum

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.cli.dependencies import build_recommend_use_case

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


class FailOn(str, Enum):
    NONE = "none"
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


_FAIL_ON_COUNT = {
    FailOn.CRITICAL: lambda a: a.scan.critical_count,
    FailOn.HIGH: lambda a: a.scan.critical_count + a.scan.high_count,
    FailOn.MEDIUM: lambda a: a.scan.critical_count + a.scan.high_count + a.scan.medium_count,
}


def recommend(
    image: str = typer.Argument(help="Docker image name (e.g., node, python, nginx)"),
    max_critical: int = typer.Option(0, "--max-critical", help="Max critical vulns allowed"),
    max_high: int = typer.Option(0, "--max-high", help="Max high vulns allowed"),
    max_medium: int = typer.Option(5, "--max-medium", help="Max medium vulns allowed"),
    limit: int = typer.Option(100, "--limit", "-l", help="Max tags to scan"),
    workers: int = typer.Option(10, "--workers", "-w", help="Concurrent workers"),
    fail_on: FailOn = typer.Option(
        FailOn.NONE, "--fail-on", help="Exit non-zero if the top result has vulns at/above this severity"
    ),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table or json"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
) -> None:
    """Recommend the most secure Docker image tags."""
    if no_color:
        console.no_color = True
    asyncio.run(_recommend(image, max_critical, max_high, max_medium, limit, workers, fail_on, format))


async def _recommend(
    image: str, max_critical: int, max_high: int,
    max_medium: int, limit: int, workers: int,
    fail_on: FailOn, format: str,
) -> None:
    use_case = await build_recommend_use_case(
        max_critical=max_critical, max_high=max_high,
        max_medium=max_medium, workers=workers,
    )
    result = await use_case.execute(image, limit=limit)

    if format == "json":
        console.print(json.dumps(result.model_dump(), indent=2, default=str))
    elif result.baseline_met and result.recommendations:
        console.print(Panel("[bold green]Recommended Images[/bold green]", expand=False))
        _print_table(result.recommendations)
    elif result.alternatives:
        console.print(Panel(
            "[bold yellow]No image found matching baseline.\n"
            "Alternative Recommendations:[/bold yellow]", expand=False,
        ))
        _print_table(result.alternatives)
    else:
        console.print("[red]No suitable images found.[/red]")
        if result.errors:
            for err in result.errors[:5]:
                console.print(f"  [dim]{err}[/dim]")

    raise typer.Exit(_exit_code(result, fail_on))


def _exit_code(result, fail_on: FailOn) -> int:
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


def _print_table(analyses: list[ImageAnalysis]) -> None:
    table = Table()
    table.add_column("#", justify="right", style="dim")
    table.add_column("Image", style="cyan bold")
    table.add_column("Score", justify="right", style="green")
    table.add_column("Tier", justify="center")
    table.add_column("Critical", justify="right", style="red")
    table.add_column("High", justify="right", style="yellow")
    table.add_column("Medium", justify="right")
    table.add_column("Fixable", justify="right", style="green")
    table.add_column("Remediation", justify="right")

    styles = {"S": "bold green", "A": "bold blue", "B": "bold yellow", "C": "bold red"}
    for i, a in enumerate(analyses, 1):
        ts = styles.get(a.tier, "")
        table.add_row(
            str(i), a.image.full_reference, str(a.security_score),
            f"[{ts}]{a.tier}[/{ts}]" if ts else a.tier,
            str(a.scan.critical_count), str(a.scan.high_count),
            str(a.scan.medium_count), str(a.scan.fixable_count),
            f"{a.remediation_score}%",
        )
    console.print(table)
