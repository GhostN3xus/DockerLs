"""Comando CLI para análise de Dockerfiles."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dockerls.application.use_cases.analyze_dockerfile import (
    AnalyzeDockerfileRequest,
    AnalyzeDockerfileUseCase,
)
from dockerls.cli.dependencies import enable_console_logging
from dockerls.infrastructure.dockerfile_validator import DockerfileValidator, HardeningTemplates

console = Console()


def analyze(
    path: str = typer.Argument(".", help="Caminho para o Dockerfile ou diretório"),
    validate_only: bool = typer.Option(
        False, "--validate-only", help="Apenas valida sem sugerir melhorias"
    ),
    suggestions: bool = typer.Option(
        True, "--suggestions/--no-suggestions", help="Mostra sugestões de hardening"
    ),
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Formato de saída: table ou json"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Habilita logs detalhados"),
) -> None:
    """Analisa um Dockerfile em busca de problemas de segurança."""
    if verbose:
        enable_console_logging()

    validator = DockerfileValidator()
    template_provider = HardeningTemplates()
    use_case = AnalyzeDockerfileUseCase(validator, template_provider)

    request = AnalyzeDockerfileRequest(
        dockerfile_path=path,
        include_suggestions=suggestions,
        validate_only=validate_only,
    )

    response = use_case.execute(request)

    if not response.success:
        console.print(f"[red]Error:[/red] {response.error}")
        raise typer.Exit(1)

    if output_format == "json":
        console.print(json.dumps(response.model_dump(), indent=2))
        return

    _print_table_output(response)


def _print_table_output(response) -> None:
    """Imprime resultado formatado em tabela."""
    validation = response.validation

    # Header
    console.print(
        Panel(
            f"[bold cyan]Dockerfile Analysis Report[/bold cyan]\n"
            f"[dim]{validation.dockerfile_path}[/dim]",
            expand=False,
        )
    )
    console.print()

    # Summary
    status_color = "green" if validation.errors == 0 else "red"
    console.print(
        f"[{status_color} bold]Summary:[/{status_color} bold] "
        f"✅ {validation.passed} passed | "
        f"⚠️ {validation.warnings} warnings | "
        f"❌ {validation.errors} errors"
    )
    console.print()

    # Validation checks table
    table = Table(title="Validation Checks", expand=False)
    table.add_column("Status", style="bold", width=8)
    table.add_column("Check", style="cyan")
    table.add_column("Message", style="white")
    table.add_column("Severity", justify="center")

    for check in validation.checks:
        if check.status.value == "PASS":
            status_icon = "[green]✅ PASS[/green]"
        elif check.status.value == "WARN":
            status_icon = "[yellow]⚠️ WARN[/yellow]"
        else:
            status_icon = "[red]❌ FAIL[/red]"

        severity_style = {
            "CRITICAL": "red bold",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "dim",
            "INFO": "dim",
        }.get(check.severity.value, "")

        table.add_row(
            status_icon,
            check.check,
            check.message,
            f"[{severity_style}]{check.severity.value}[/{severity_style}]"
            if severity_style
            else check.severity.value,
        )

    console.print(table)
    console.print()

    # Security score
    if response.analysis:
        score = response.analysis.security_score
        tier = response.analysis.security_tier

        tier_colors = {"A": "green", "B": "yellow", "C": "red"}
        tier_color = tier_colors.get(tier, "white")

        console.print(
            Panel(
                f"[bold]Security Score: {score}/100[/bold]\n"
                f"Tier: [{tier_color} bold]{tier}[/{tier_color} bold]\n"
                f"Production Ready: {'[green]Yes[/green]' if response.analysis.is_production_ready else '[red]No[/red]'}",
                expand=False,
            )
        )
        console.print()

    # Suggestions
    if response.suggestions:
        console.print(Panel("[bold yellow]💡 Recommendations[/bold yellow]", expand=False))

        for i, suggestion in enumerate(response.suggestions, 1):
            priority_colors = {
                "CRITICAL": "red bold",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "dim",
            }
            priority_color = priority_colors.get(suggestion.priority.value, "")

            console.print(f"\n[{priority_color}]#{i}. {suggestion.title}[/{priority_color}]")
            console.print(f"   [dim]{suggestion.description}[/dim]")
            console.print(f"   Current: [yellow]{suggestion.current_state}[/yellow]")
            console.print(f"   Fix: [green]{suggestion.suggested_fix}[/green]")
            console.print(f"   [italic]Reason: {suggestion.reason}[/italic]")

        console.print()

    # Exit code based on validation
    if validation.errors > 0:
        raise typer.Exit(2)
    elif validation.warnings > 0:
        raise typer.Exit(0)  # Warnings não falham o build
    else:
        raise typer.Exit(0)
