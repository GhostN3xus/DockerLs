from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dockerls.cli.dependencies import build_compare_use_case

if TYPE_CHECKING:
    from dockerls.application.dto.analysis import ComparisonResult

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
            a.image.full_reference,
            str(a.security_score),
            a.tier,
            str(a.scan.critical_count),
            str(a.scan.high_count),
            str(a.scan.medium_count),
            str(a.scan.total_count),
            str(a.scan.fixable_count),
            f"{a.remediation_score}/100",
        )
    console.print(table)

    _print_verdict(result)


def _print_verdict(result: ComparisonResult) -> None:
    """Vencedor primeiro, depois cada perdedor com o próprio delta.

    A versão anterior juntava tudo numa linha -- vencedor, score absoluto e
    diferença separados por ponto e vírgula --, e o `-36.0 points` do final
    lia como um score negativo em vez de uma distância até o vencedor.
    """
    winner = next((a for a in result.images if a.image.full_reference == result.winner), None)
    if winner is None:
        return

    console.print(
        f"\n[bold green]Winner: {winner.image.full_reference}[/bold green] "
        f"[dim](Score {winner.security_score}, Tier {winner.tier})[/dim]"
    )
    for a in result.images:
        if a.image.full_reference == result.winner:
            continue
        delta = a.security_score - winner.security_score
        console.print(
            f"  {a.image.full_reference}  Score {a.security_score}, Tier {a.tier}  "
            f"[dim]({delta:+.1f} vs. winner)[/dim]"
        )

    if result.common_vulns:
        console.print(f"\n[bold]Shared vulnerabilities:[/bold] {len(result.common_vulns)}")
    for reference, vulns in result.unique_vulns.items():
        if vulns:
            console.print(f"[dim]Unique to {reference}: {len(vulns)}[/dim]")
