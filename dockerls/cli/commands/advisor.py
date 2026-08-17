from __future__ import annotations

import asyncio
import json

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dockerls.application.services.ecosystems import get_ecosystem_insights
from dockerls.application.use_cases.recommend_images import build_recommendation
from dockerls.cli.dependencies import build_recommend_use_case
from dockerls.cli.options import OutputFormat, parse_output_format
from dockerls.cli.validators import check_workers
from dockerls.exit_codes import EXIT_ERROR

console = Console()


def advisor(
    image: str = typer.Argument(help="Docker image name (e.g., node, python, nginx)"),
    workers: int | None = typer.Option(
        None, "--workers", "-w", help="Concurrent workers [config: workers, default 10]"
    ),
    output_format: str = typer.Option(
        OutputFormat.TABLE.value, "--format", "-f", help="Output format: table or json"
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
) -> None:
    """Security advisor: analyze and provide actionable remediation plan."""
    if no_color:
        console.no_color = True
    fmt = parse_output_format(output_format)
    if workers is not None:
        workers = check_workers(workers)
    try:
        asyncio.run(_advisor(image, workers, fmt))
    except ValueError as e:
        console.print(f"[red]Invalid configuration:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e


async def _advisor(image: str, workers: int | None, output_format: OutputFormat) -> None:
    use_case = await build_recommend_use_case(workers=workers)
    result = await use_case.execute(image)

    items = result.recommendations or result.alternatives
    if not items:
        if output_format == OutputFormat.JSON:
            error_payload = {"error": "No images found to advise on", "errors": result.errors}
            console.print(json.dumps(error_payload), soft_wrap=True)
        else:
            console.print("[red]No images found to advise on.[/red]")
        raise typer.Exit(EXIT_ERROR)

    best = items[0]
    rec = best.recommendation or build_recommendation(best)
    insights = get_ecosystem_insights(best.image.full_reference or image)

    if output_format == OutputFormat.JSON:
        payload = best.model_dump()
        payload["remediation"] = rec.model_dump()
        payload["ecosystem_insights"] = {
            "ecosystem": insights.ecosystem,
            "version": insights.version,
            "runtime_features": insights.runtime_features,
            "base_distro_advice": insights.base_distro_advice,
            "security_guidelines": insights.security_guidelines,
            "common_pitfalls": insights.common_pitfalls,
            "snippets": insights.recommended_dockerfile_snippets,
        }
        console.print(json.dumps(payload, indent=2, default=str), soft_wrap=True)
        return

    console.print(
        Panel(f"[bold cyan]🐳 DockerLs Security Advisor: {image}[/bold cyan]", expand=False)
    )
    console.print()

    info = Table(show_header=False, box=None, padding=(0, 2))
    info.add_column("Key", style="bold")
    info.add_column("Value")
    info.add_row("Current Best Image", f"[cyan]{best.image.full_reference}[/cyan]")
    info.add_row("Ecosystem / Runtime", f"{insights.ecosystem} ({insights.version})")
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

    if insights.base_distro_advice or insights.security_guidelines:
        console.print()
        console.print(
            Panel(
                "[bold magenta]🔍 Ecosystem Particularities & Hardening[/bold magenta]",
                expand=False,
            )
        )
        if insights.base_distro_advice:
            console.print("\n[bold]Base Image & Distribution Notes:[/bold]")
            for advice in insights.base_distro_advice:
                console.print(f"  • {advice}")
        if insights.security_guidelines:
            console.print("\n[bold]Production & Security Guidelines:[/bold]")
            for item in insights.security_guidelines:
                console.print(f"  • {item}")
        if insights.common_pitfalls:
            console.print("\n[bold red]Common Pitfalls to Avoid:[/bold red]")
            for pit in insights.common_pitfalls:
                console.print(f"  ⚠️ {pit}")

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
