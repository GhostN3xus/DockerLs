from __future__ import annotations

import asyncio
import json

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dockerls.application.use_cases.recommend_images import build_recommendation
from dockerls.cli.dependencies import build_recommend_use_case

console = Console()


def advisor(
    image: str = typer.Argument(help="Docker image name (e.g., node, python, nginx)"),
    workers: int = typer.Option(10, "--workers", "-w", help="Concurrent workers"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table or json"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
) -> None:
    """Security advisor: analyze and provide actionable remediation plan."""
    if no_color:
        console.no_color = True
    asyncio.run(_advisor(image, workers, format))


async def _advisor(image: str, workers: int, format: str) -> None:
    use_case = await build_recommend_use_case(workers=workers)
    result = await use_case.execute(image)

    items = result.recommendations or result.alternatives
    if not items:
        if format == "json":
            console.print(json.dumps({"error": "No images found to advise on", "errors": result.errors}))
        else:
            console.print("[red]No images found to advise on.[/red]")
        raise typer.Exit(1)

    best = items[0]
    rec = best.recommendation or build_recommendation(best)

    if format == "json":
        payload = best.model_dump()
        payload["remediation"] = rec.model_dump()
        console.print(json.dumps(payload, indent=2, default=str))
        return

    console.print(Panel(f"[bold]Security Advisor: {image}[/bold]", expand=False))
    console.print()

    info = Table(show_header=False, box=None, padding=(0, 2))
    info.add_column("Key", style="bold")
    info.add_column("Value")
    info.add_row("Current Best Image", f"[cyan]{best.image.full_reference}[/cyan]")
    info.add_row("Security Score", f"[green]{best.security_score}[/green]")
    info.add_row("Tier", best.tier)
    info.add_row("Critical", f"[red]{best.scan.critical_count}[/red]")
    info.add_row("High", f"[yellow]{best.scan.high_count}[/yellow]")
    info.add_row("Medium", str(best.scan.medium_count))
    info.add_row("Fixable High", str(best.scan.fixable_high_count))
    info.add_row("Remediation Score", f"{best.remediation_score}%")
    info.add_row("EOL", "Yes" if best.is_eol else "No")
    info.add_row("LTS", "Yes" if best.is_lts else "No")
    console.print(info)

    if rec.steps:
        console.print()
        console.print("[bold]Remediation Plan[/bold]")
        console.print()
        for step in rec.steps:
            desc = step.description
            if step.from_value and step.to_value:
                desc += f" [dim]({step.from_value} -> {step.to_value})[/dim]"
            console.print(f"  STEP {step.step_number}: {desc}")
            if step.expected_impact:
                console.print(f"         [dim]{step.expected_impact}[/dim]")

    if rec.summary:
        console.print()
        console.print(f"[bold]Summary:[/bold] {rec.summary}")
