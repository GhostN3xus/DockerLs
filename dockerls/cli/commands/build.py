"""Comando CLI para build seguro de imagens Docker."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel

from dockerls.application.use_cases.build_image import (
    BuildImageRequest,
    BuildImageResponse,
    BuildImageUseCase,
    BuildReport,
)
from dockerls.cli.dependencies import enable_console_logging
from dockerls.cli.rendering import render_validation_report
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK
from dockerls.infrastructure.dockerfile_validator import DockerfileValidator, HardeningTemplates

console = Console()


def build(
    path: str = typer.Argument(".", help="Diretório com Dockerfile"),
    tag: str | None = typer.Option(None, "--tag", "-t", help="Tag da imagem (obrigatório)"),
    base: str | None = typer.Option(
        None, "--base", help="Imagem base recomendada (node, python, go)"
    ),
    hardened: bool = typer.Option(False, "--hardened", help="Usa templates Dockerfile hardened"),
    list_templates: bool = typer.Option(
        False, "--list-templates", help="Lista os templates hardened disponíveis e sai"
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Wizard de segurança passo a passo"
    ),
    scan: bool = typer.Option(True, "--scan/--no-scan", help="Executa Trivy/Grype após build"),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Reprova build se tiver critical/high"
    ),
    report: str | None = typer.Option(
        None, "--report", "-r", help="Salva relatório de segurança (JSON/HTML)"
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Desativa cache do Docker"),
    build_args: str | None = typer.Option(None, "--build-args", help="Argumentos de build (JSON)"),
    labels: str | None = typer.Option(None, "--labels", help="Labels de segurança (JSON)"),
    ci_mode: bool = typer.Option(
        False, "--ci-mode", help="Modo CI/CD (output JSON, sem interação)"
    ),
    validate_only: bool = typer.Option(False, "--validate-only", help="Apenas valida Dockerfile"),
    suggest_hardening: bool = typer.Option(
        False, "--suggest-hardening", help="Sugere melhorias sem build"
    ),
    config: str | None = typer.Option(
        None, "--config", help="Arquivo de config .dockerls-hardening.yaml"
    ),
    push: bool = typer.Option(False, "--push", help="Push para registry após build"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug detalhado"),
    output: str | None = typer.Option(None, "--output", "-o", help="Arquivo de saída do relatório"),
    force: bool = typer.Option(False, "--force", help="Força build mesmo com erros de validação"),
) -> None:
    """Constrói imagens Docker seguras com validação e scanning."""
    if verbose:
        enable_console_logging()

    template_provider = HardeningTemplates()

    if list_templates:
        _print_templates(template_provider, ci_mode=ci_mode)
        raise typer.Exit(EXIT_OK)

    # Validar tag obrigatória (exceto em modos especiais)
    if not tag and not validate_only and not suggest_hardening:
        console.print("[red]Error:[/red] --tag é obrigatório para build")
        raise typer.Exit(EXIT_ERROR)

    # Parsear JSON args
    build_args_dict = _parse_json_option(build_args, "--build-args")
    labels_dict = _parse_json_option(labels, "--labels")

    # Inicializar use case
    validator = DockerfileValidator()
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
    response = _run_interactive_wizard(use_case, path) if interactive else use_case.execute(request)

    # Output
    if ci_mode or output:
        _print_json_output(response, output)
    else:
        _print_table_output(response, report)

    raise typer.Exit(response.exit_code)


def _parse_json_option(raw: str | None, flag: str) -> dict[str, str] | None:
    """Parseia um argumento JSON de linha de comando, ou aborta com exit 1."""
    if not raw:
        return None
    try:
        parsed: dict[str, str] = json.loads(raw)
    except json.JSONDecodeError as e:
        console.print(f"[red]Error parsing {flag}:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e
    return parsed


def _print_templates(template_provider: HardeningTemplates, ci_mode: bool = False) -> None:
    """Lista os templates hardened que `--base`/`--hardened` aceitam."""
    templates = template_provider.list_templates()
    if ci_mode:
        typer.echo(json.dumps({"templates": templates}, indent=2))
        return

    console.print(Panel("[bold cyan]Hardened Dockerfile templates[/bold cyan]", expand=False))
    for name in templates:
        console.print(f"  • [cyan]{name}[/cyan]")
    console.print("\n[dim]Use with: dockerls build --hardened --base <template> -t <tag>[/dim]")


def _run_interactive_wizard(use_case: BuildImageUseCase, path: str) -> BuildImageResponse:
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

    answers: dict[str, str] = {}
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
                continue

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


def _print_table_output(response: BuildImageResponse, report_file: str | None = None) -> None:
    """Imprime resultado formatado em tabela."""
    # Nenhuma imagem construída: o resultado é a validação, e é ela que
    # precisa aparecer -- com os checks, não só com um veredito.
    if response.image_tag is None:
        _print_validation_output(response, report_file)
        return

    _print_build_output(response, report_file)


def _print_validation_output(response: BuildImageResponse, report_file: str | None) -> None:
    if response.validation is not None:
        render_validation_report(
            console,
            response.validation,
            analysis=response.analysis,
            suggestions=list(response.recommendations) or None,
            title="Dockerfile Validation",
        )

    if response.success:
        console.print(
            Panel(
                "[bold green]✅ Validation Passed[/bold green]\n"
                "[dim]No blocking policy violations found[/dim]",
                expand=False,
            )
        )
    else:
        console.print(
            Panel(
                f"[bold red]❌ Validation Failed[/bold red]\n\n"
                f"[red]{response.error or 'Dockerfile validation failed'}[/red]",
                expand=False,
            )
        )

    _write_report_file(response.report, report_file)
    console.print()


def _print_build_output(response: BuildImageResponse, report_file: str | None) -> None:
    if not response.success:
        console.print(
            Panel(
                f"[bold red]❌ Build Failed[/bold red]\n\n"
                f"[red]{response.error or 'Build failed'}[/red]",
                expand=False,
            )
        )
        _write_report_file(response.report, report_file)
        return

    console.print(
        Panel(
            f"[bold green]✅ Build Successful[/bold green]\n[dim]{response.image_tag}[/dim]",
            expand=False,
        )
    )
    console.print()

    report = response.report
    if report is not None:
        _print_report(report)
        _write_report_file(report, report_file)

    if response.recommendations:
        console.print(Panel("[bold yellow]💡 Hardening Suggestions[/bold yellow]", expand=False))
        for i, rec in enumerate(response.recommendations[:3], 1):
            console.print(f"\n{i}. [bold]{rec.title}[/bold]")
            console.print(f"   [dim]{rec.description}[/dim]")
            console.print(f"   Fix: [green]{rec.suggested_fix}[/green]")

    console.print()


def _print_report(report: BuildReport) -> None:
    tier_colors = {"A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "red"}
    tier_color = tier_colors.get(report.security_tier, "white")

    console.print(
        Panel(
            f"[bold]Security Score: {report.security_score}/100[/bold]\n"
            f"Tier: [{tier_color} bold]{report.security_tier}[/{tier_color} bold]",
            expand=False,
        )
    )
    console.print()

    validation = report.validation
    console.print(
        f"✅ Validation: {validation.get('passed', 0)} passed | "
        f"⚠️ {validation.get('warnings', 0)} warnings | "
        f"❌ {validation.get('errors', 0)} errors"
    )
    console.print()

    if report.scan_results:
        console.print(Panel("[bold magenta]🔍 Security Scan Results[/bold magenta]", expand=False))
        scan_data = next(iter(report.scan_results.values()))
        console.print(f"  CRITICAL: [red]{scan_data.get('critical', 0)}[/red]")
        console.print(f"  HIGH: [red]{scan_data.get('high', 0)}[/red]")
        console.print(f"  MEDIUM: [yellow]{scan_data.get('medium', 0)}[/yellow]")
        console.print(f"  LOW: [dim]{scan_data.get('low', 0)}[/dim]")
        console.print()

    if report.recommendations:
        console.print(Panel("[bold yellow]💡 Recommendations[/bold yellow]", expand=False))
        priority_colors = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}
        for i, rec in enumerate(report.recommendations[:5], 1):
            priority = str(rec.get("priority", "MEDIUM"))
            priority_color = priority_colors.get(priority, "white")
            console.print(f"\n[{priority_color}]#{i}. {rec.get('title', '-')}[/{priority_color}]")
            console.print(f"   [dim]{rec.get('reason', '-')}[/dim]")
            console.print(f"   Fix: [green]{rec.get('suggested', '-')}[/green]")
        console.print()


def _write_report_file(report: BuildReport | None, report_file: str | None) -> None:
    if report is None or not report_file:
        return
    _save_report(report, report_file)
    console.print(f"\n📄 Report saved: [cyan]{report_file}[/cyan]")


def _report_dict(report: BuildReport) -> dict[str, Any]:
    return {
        "build_id": report.build_id,
        "timestamp": report.timestamp,
        "image": report.image,
        "dockerfile_path": report.dockerfile_path,
        "security_score": report.security_score,
        "security_tier": report.security_tier,
        "validation": report.validation,
        "scan_results": report.scan_results,
        "recommendations": report.recommendations,
        "build_metadata": report.build_metadata,
    }


def _print_json_output(response: BuildImageResponse, output_file: str | None = None) -> None:
    """Imprime saída JSON (CI mode).

    Vai para stdout via `typer.echo`, não pelo console do Rich: em CI o
    consumidor é um parser, e cor ou quebra de linha por largura de terminal
    quebrariam o JSON.
    """
    output_data: dict[str, Any] = {
        "status": "SUCCESS" if response.success else "FAILED",
        "exit_code": response.exit_code,
    }

    # O relatório entra sempre que existe -- inclusive numa validação
    # reprovada, que é justamente quando o CI precisa saber o que falhou.
    if response.report is not None:
        output_data["report"] = _report_dict(response.report)
    if response.error:
        output_data["error"] = response.error

    json_output = json.dumps(output_data, indent=2)

    if output_file:
        Path(output_file).write_text(json_output)
        console.print(f"Report saved to {output_file}", style="dim")
    else:
        typer.echo(json_output)


def _save_report(report: BuildReport, filepath: str) -> None:
    """Salva relatório em arquivo."""
    path = Path(filepath)

    if path.suffix.lower() in (".html", ".htm"):
        path.write_text(_render_html_report(report))
        return

    path.write_text(json.dumps(_report_dict(report), indent=2))


def _render_html_report(report: BuildReport) -> str:
    score_color = "#22c55e" if report.security_score >= 75 else "#ef4444"
    tier_color = "#22c55e" if report.security_tier == "A" else "#ef4444"
    validation = report.validation

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>DockerLs Build Report - {report.image or report.dockerfile_path}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .score {{ font-size: 48px; font-weight: bold; color: {score_color}; }}
        .tier {{ font-size: 24px; color: {tier_color}; }}
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
    <p><strong>Image:</strong> {report.image or "(not built)"}</p>
    <p><strong>Dockerfile:</strong> {report.dockerfile_path}</p>
    <p><strong>Timestamp:</strong> {report.timestamp}</p>

    <h2>Security Assessment</h2>
    <div class="score">{report.security_score}/100</div>
    <div class="tier">Tier: {report.security_tier}</div>

    <h2>Validation Results</h2>
    <table>
        <tr><th>Passed</th><td>{validation.get("passed", 0)}</td></tr>
        <tr><th>Warnings</th><td>{validation.get("warnings", 0)}</td></tr>
        <tr><th>Errors</th><td>{validation.get("errors", 0)}</td></tr>
    </table>

    <h2>Vulnerability Scan</h2>
"""

    if report.scan_results:
        scan = next(iter(report.scan_results.values()))
        html += f"""
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        <tr><td class="critical">Critical</td><td>{scan.get("critical", 0)}</td></tr>
        <tr><td class="high">High</td><td>{scan.get("high", 0)}</td></tr>
        <tr><td class="medium">Medium</td><td>{scan.get("medium", 0)}</td></tr>
        <tr><td class="low">Low</td><td>{scan.get("low", 0)}</td></tr>
    </table>
"""
    else:
        html += "    <p>No scan was run.</p>\n"

    return (
        html
        + """
</body>
</html>"""
    )
