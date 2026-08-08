"""Comando CLI para build seguro de imagens Docker."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from dockerls.application.use_cases.build_image import (
    BuildImageRequest,
    BuildImageUseCase,
)
from dockerls.cli.dependencies import enable_console_logging
from dockerls.infrastructure.dockerfile_validator import DockerfileValidator, HardeningTemplates

console = Console()


def build(
    path: str = typer.Argument(".", help="Diretório com Dockerfile"),
    tag: Optional[str] = typer.Option(None, "--tag", "-t", help="Tag da imagem (obrigatório)"),
    base: Optional[str] = typer.Option(None, "--base", help="Imagem base recomendada (node, python, go)"),
    hardened: bool = typer.Option(False, "--hardened", help="Usa templates Dockerfile hardened"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Wizard de segurança passo a passo"),
    scan: bool = typer.Option(True, "--scan/--no-scan", help="Executa Trivy/Grype após build"),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Reprova build se tiver critical/high"),
    report: Optional[str] = typer.Option(None, "--report", "-r", help="Salva relatório de segurança (JSON/HTML)"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Desativa cache do Docker"),
    build_args: Optional[str] = typer.Option(None, "--build-args", help="Argumentos de build (JSON)"),
    labels: Optional[str] = typer.Option(None, "--labels", help="Labels de segurança (JSON)"),
    ci_mode: bool = typer.Option(False, "--ci-mode", help="Modo CI/CD (output JSON, sem interação)"),
    validate_only: bool = typer.Option(False, "--validate-only", help="Apenas valida Dockerfile"),
    suggest_hardening: bool = typer.Option(False, "--suggest-hardening", help="Sugere melhorias sem build"),
    config: Optional[str] = typer.Option(None, "--config", help="Arquivo de config .dockerls-hardening.yaml"),
    push: bool = typer.Option(False, "--push", help="Push para registry após build"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug detalhado"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Arquivo de saída do relatório"),
    force: bool = typer.Option(False, "--force", help="Força build mesmo com erros de validação"),
) -> None:
    """Constrói imagens Docker seguras com validação e scanning."""
    if verbose:
        enable_console_logging()

    # Validar tag obrigatória (exceto em modos especiais)
    if not tag and not validate_only and not suggest_hardening:
        console.print("[red]Error:[/red] --tag é obrigatório para build")
        raise typer.Exit(1)

    # Parsear JSON args
    build_args_dict = None
    if build_args:
        try:
            build_args_dict = json.loads(build_args)
        except json.JSONDecodeError as e:
            console.print(f"[red]Error parsing --build-args:[/red] {e}")
            raise typer.Exit(1)

    labels_dict = None
    if labels:
        try:
            labels_dict = json.loads(labels)
        except json.JSONDecodeError as e:
            console.print(f"[red]Error parsing --labels:[/red] {e}")
            raise typer.Exit(1)

    # Inicializar use case
    validator = DockerfileValidator()
    template_provider = HardeningTemplates()
    use_case = BuildImageUseCase(validator, template_provider)

    # Criar request
    request = BuildImageRequest(
        context_path=path,
        tag=tag or "temp:latest",
        dockerfile_path="Dockerfile",
        hardened=hardened,
        base_template=base,
        scan=scan,
        validate_only=validate_only,
        suggest_only=suggest_hardening,
        no_cache=no_cache,
        build_args=build_args_dict,
        labels=labels_dict,
        fail_on=fail_on,
        ci_mode=ci_mode,
        verbose=verbose,
        force=force,
    )

    # Executar
    if interactive:
        response = _run_interactive_wizard(use_case, path)
    else:
        response = use_case.execute(request)

    # Output
    if ci_mode or output:
        _print_json_output(response, output)
    else:
        _print_table_output(response, report)

    # Exit code
    if response.success:
        raise typer.Exit(0)
    else:
        raise typer.Exit(response.exit_code or 1)


def _run_interactive_wizard(use_case: BuildImageUseCase, path: str) -> any:
    """Executa wizard interativo."""
    console.print(Panel("[bold cyan]DockerLs Interactive Build Wizard[/bold cyan]", expand=False))
    console.print()

    # Perguntas
    questions = [
        ("base", "What's your application type?", ["node", "python", "go", "java", "other"]),
        ("hardened", "Use hardened template?", ["yes", "no"]),
        ("scan", "Scan after build?", ["yes", "no"]),
        ("report_format", "Export report?", ["json", "html", "both", "none"]),
        ("push", "Push to registry?", ["dockerhub", "ghcr", "harbor", "no"]),
    ]

    answers = {}
    for key, question, options in questions:
        console.print(f"\n[bold yellow]? {question}[/bold yellow]")
        for i, opt in enumerate(options):
            console.print(f"  {i + 1}. {opt}")

        while True:
            try:
                choice = console.input("\nChoice [1]: ")
                if not choice:
                    choice = "1"
                idx = int(choice) - 1
                if 0 <= idx < len(options):
                    answers[key] = options[idx]
                    break
            except ValueError:
                pass

    # Construir request baseado nas respostas
    base_template = answers.get("base", "node")
    if base_template == "other":
        base_template = "node"

    hardened = answers.get("hardened", "yes") == "yes"
    scan = answers.get("scan", "yes") == "yes"

    # Tag
    tag = console.input("\nImage tag [app:latest]: ") or "app:latest"

    request = BuildImageRequest(
        context_path=path,
        tag=tag,
        hardened=hardened,
        base_template=base_template if hardened else None,
        scan=scan,
    )

    return use_case.execute(request)


def _print_table_output(response: any, report_file: Optional[str] = None) -> None:
    """Imprime resultado formatado em tabela."""
    if not response.success:
        console.print(
            Panel(
                f"[bold red]❌ Build Failed[/bold red]\n\n"
                f"[red]{response.error}[/red]",
                expand=False,
            )
        )
        return

    # Header
    console.print(
        Panel(
            "[bold green]✅ Build Successful[/bold green]\n"
            f"[dim]{response.image_tag}[/dim]",
            expand=False,
        )
    )
    console.print()

    # Show report if available
    if response.report:
        report = response.report

        # Security score
        score = report.security_score
        tier = report.security_tier

        tier_colors = {"A": "green", "B": "yellow", "C": "orange", "D": "red", "F": "red"}
        tier_color = tier_colors.get(tier, "white")

        console.print(
            Panel(
                f"[bold]Security Score: {score}/100[/bold]\n"
                f"Tier: [{tier_color} bold]{tier}[/{tier_color} bold]",
                expand=False,
            )
        )
        console.print()

        # Validation summary
        validation = report.validation
        console.print(
            f"✅ Validation: {validation['passed']} passed | "
            f"⚠️ {validation['warnings']} warnings | "
            f"❌ {validation['errors']} errors"
        )
        console.print()

        # Scan results
        if report.scan_results:
            console.print(Panel("[bold magenta]🔍 Security Scan Results[/bold magenta]", expand=False))

            scan_data = list(report.scan_results.values())[0]
            console.print(f"  CRITICAL: [red]{scan_data.get('critical', 0)}[/red]")
            console.print(f"  HIGH: [red]{scan_data.get('high', 0)}[/red]")
            console.print(f"  MEDIUM: [yellow]{scan_data.get('medium', 0)}[/yellow]")
            console.print(f"  LOW: [dim]{scan_data.get('low', 0)}[/dim]")
            console.print()

        # Recommendations
        if report.recommendations:
            console.print(Panel("[bold yellow]💡 Recommendations[/bold yellow]", expand=False))
            for i, rec in enumerate(report.recommendations[:5], 1):
                priority = rec.get("priority", "MEDIUM")
                priority_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}.get(priority, "")

                console.print(f"\n[{priority_color}]#{i}. {rec.get('title')}[/{priority_color}]")
                console.print(f"   [dim]{rec.get('reason')}[/dim]")
                console.print(f"   Fix: [green]{rec.get('suggested')}[/green]")

        # Save report if requested
        if report_file:
            _save_report(report, report_file)
            console.print(f"\n📄 Report saved: [cyan]{report_file}[/cyan]")

    # Recommendations from use case
    if response.recommendations:
        console.print(Panel("[bold yellow]💡 Hardening Suggestions[/bold yellow]", expand=False))
        for i, rec in enumerate(response.recommendations[:3], 1):
            console.print(f"\n{i}. [bold]{rec.title}[/bold]")
            console.print(f"   [dim]{rec.description}[/dim]")
            console.print(f"   Fix: [green]{rec.suggested_fix}[/green]")

    console.print()


def _print_json_output(response: any, output_file: Optional[str] = None) -> None:
    """Imprime saída JSON (CI mode)."""
    output_data = {
        "status": "SUCCESS" if response.success else "FAILED",
        "exit_code": response.exit_code,
    }

    if response.success and response.report:
        output_data["report"] = {
            "build_id": response.report.build_id,
            "timestamp": response.report.timestamp,
            "image": response.report.image,
            "security_score": response.report.security_score,
            "security_tier": response.report.security_tier,
            "validation": response.report.validation,
            "scan_results": response.report.scan_results,
            "recommendations": response.report.recommendations,
            "build_metadata": response.report.build_metadata,
        }
    elif response.error:
        output_data["error"] = response.error

    json_output = json.dumps(output_data, indent=2)

    if output_file:
        Path(output_file).write_text(json_output)
        console.print(f"Report saved to {output_file}", style="dim")
    else:
        console.print(json_output)


def _save_report(report: any, filepath: str) -> None:
    """Salva relatório em arquivo."""
    path = Path(filepath)

    if path.suffix.lower() == ".json":
        data = {
            "build_id": report.build_id,
            "timestamp": report.timestamp,
            "image": report.image,
            "security_score": report.security_score,
            "security_tier": report.security_tier,
            "validation": report.validation,
            "scan_results": report.scan_results,
            "recommendations": report.recommendations,
            "build_metadata": report.build_metadata,
        }
        path.write_text(json.dumps(data, indent=2))

    elif path.suffix.lower() in [".html", ".htm"]:
        # HTML simples
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>DockerLs Build Report - {report.image}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .score {{ font-size: 48px; font-weight: bold; color: {'#22c55e' if report.security_score >= 75 else '#ef4444'}; }}
        .tier {{ font-size: 24px; color: {'#22c55e' if report.security_tier == 'A' else '#ef4444'}; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f3f4f6; }}
        .critical {{ color: #dc2626; }}
        .high {{ color: #dc2626; }}
        .medium {{ color: #f59e0b; }}
        .low {{ color: #6b7280; }}
    </style>
</head>
<body>
    <h1>🐳 DockerLs Build Report</h1>
    <p><strong>Image:</strong> {report.image}</p>
    <p><strong>Timestamp:</strong> {report.timestamp}</p>
    
    <h2>Security Assessment</h2>
    <div class="score">{report.security_score}/100</div>
    <div class="tier">Tier: {report.security_tier}</div>
    
    <h2>Validation Results</h2>
    <table>
        <tr><th>Passed</th><td>{report.validation.get('passed', 0)}</td></tr>
        <tr><th>Warnings</th><td>{report.validation.get('warnings', 0)}</td></tr>
        <tr><th>Errors</th><td>{report.validation.get('errors', 0)}</td></tr>
    </table>
    
    <h2>Vulnerability Scan</h2>
"""
        if report.scan_results:
            scan = list(report.scan_results.values())[0]
            html += f"""
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        <tr><td class="critical">Critical</td><td>{scan.get('critical', 0)}</td></tr>
        <tr><td class="high">High</td><td>{scan.get('high', 0)}</td></tr>
        <tr><td class="medium">Medium</td><td>{scan.get('medium', 0)}</td></tr>
        <tr><td class="low">Low</td><td>{scan.get('low', 0)}</td></tr>
    </table>
"""
        
        html += """
</body>
</html>"""
        path.write_text(html)

    else:
        # Default JSON
        data = {
            "build_id": report.build_id,
            "timestamp": report.timestamp,
            "image": report.image,
            "security_score": report.security_score,
            "security_tier": report.security_tier,
            "validation": report.validation,
            "scan_results": report.scan_results,
            "recommendations": report.recommendations,
            "build_metadata": report.build_metadata,
        }
        path.write_text(json.dumps(data, indent=2))
