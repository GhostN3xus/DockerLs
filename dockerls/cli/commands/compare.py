from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dockerls.cli.dependencies import build_compare_use_case

console = Console()


def compare(
    images: list[str] = typer.Argument(help="Two or more image references to compare"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
) -> None:
    """Compare security posture of multiple Docker images."""
    if no_color:
        console.no_color = True
    if len(images) < 2:
        console.print("[red]Provide at least two images to compare.[/red]")
        raise typer.Exit(1)
    asyncio.run(_compare(images))


async def _compare(images: list[str]) -> None:
    use_case = await build_compare_use_case()
    try:
        result = await use_case.execute(images)
    except ValueError as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        raise typer.Exit(1) from e

    console.print(Panel("[bold]Image Comparison[/bold]", expand=False))

    table = Table()
    table.add_column("Image", style="cyan")
    table.add_column("Score", justify="right", style="green")
    table.add_column("Tier", justify="center")
    table.add_column("Critical", justify="right", style="red")
    table.add_column("High", justify="right", style="yellow")
    table.add_column("Medium", justify="right")
    table.add_column("Total Vulns", justify="right")
    table.add_column("Fixable", justify="right")
    table.add_column("Remediation", justify="right")

    for a in result.images:
        table.add_row(
            a.image.full_reference, str(a.security_score), a.tier,
            str(a.scan.critical_count), str(a.scan.high_count),
            str(a.scan.medium_count), str(a.scan.total_count),
            str(a.scan.fixable_count), f"{a.remediation_score}%",
        )
    console.print(table)

    if result.winner:
        console.print(f"\n[bold green]Winner: {result.winner}[/bold green]")
    if result.summary:
        console.print(f"[dim]{result.summary}[/dim]")

    if result.common_vulns:
        console.print(f"\n[bold]Shared vulnerabilities: {len(result.common_vulns)}[/bold]")
