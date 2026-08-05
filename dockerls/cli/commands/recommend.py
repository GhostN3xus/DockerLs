from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.cli.dependencies import build_recommend_use_case

console = Console()


def recommend(
    image: str = typer.Argument(help="Docker image name (e.g., node, python, nginx)"),
    max_critical: int = typer.Option(0, "--max-critical", help="Max critical vulns allowed"),
    max_high: int = typer.Option(0, "--max-high", help="Max high vulns allowed"),
    max_medium: int = typer.Option(5, "--max-medium", help="Max medium vulns allowed"),
    limit: int = typer.Option(100, "--limit", "-l", help="Max tags to scan"),
    workers: int = typer.Option(10, "--workers", "-w", help="Concurrent workers"),
) -> None:
    """Recommend the most secure Docker image tags."""
    asyncio.run(_recommend(image, max_critical, max_high, max_medium, limit, workers))


async def _recommend(
    image: str, max_critical: int, max_high: int,
    max_medium: int, limit: int, workers: int,
) -> None:
    use_case = await build_recommend_use_case(
        max_critical=max_critical, max_high=max_high,
        max_medium=max_medium, workers=workers,
    )
    result = await use_case.execute(image, limit=limit)

    if result.baseline_met and result.recommendations:
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
        raise typer.Exit(1)


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
