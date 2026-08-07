from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.syntax import Syntax
from rich.table import Table

from dockerls.application.use_cases.generate_hardened_dockerfile import TemplateGenerationError
from dockerls.cli.dependencies import build_hardening_level, build_template_generator
from dockerls.infrastructure.templates.loader import available_templates, get_template

console = Console()

templates_app = typer.Typer(
    name="templates",
    help="Production-hardened Dockerfile templates.",
    no_args_is_help=False,
    invoke_without_command=True,
)


@templates_app.callback()
def templates_root(ctx: typer.Context) -> None:
    """List the bundled templates when no subcommand is given."""
    if ctx.invoked_subcommand is None:
        templates_list()


@templates_app.command("list")
def templates_list() -> None:
    """List the available hardened templates."""
    table = Table(title="Hardened Dockerfile templates")
    table.add_column("Name", style="cyan bold")
    table.add_column("Port", justify="right", style="dim")
    table.add_column("What it gives you", overflow="fold")
    for template in available_templates():
        table.add_row(template.name, str(template.default_port), template.description)
    console.print(table)
    console.print(
        "\n[dim]dockerls templates show node          print one template\n"
        "dockerls templates generate . --base node   write Dockerfile.hardened[/dim]"
    )


@templates_app.command("show")
def templates_show(
    name: str = typer.Argument(help="Template name (node, python, go, java)"),
    raw: bool = typer.Option(False, "--raw", help="Print without syntax highlighting"),
) -> None:
    """Print a hardened template to stdout."""
    try:
        template = get_template(name)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e

    content = template.read()
    if raw or console.no_color:
        # `--raw` exists so the template can be piped straight into a file:
        # `dockerls templates show go --raw > Dockerfile`.
        console.print(content, soft_wrap=True, highlight=False, markup=False)
        return
    console.print(Syntax(content, "docker", theme="ansi_dark", line_numbers=False))


@templates_app.command("generate")
def templates_generate(
    path: str = typer.Argument(".", help="Project directory to generate into"),
    base: str = typer.Option(
        "", "--base", help="Template to use; auto-detected from the project when omitted"
    ),
    output: str = typer.Option(
        "", "--output", "-o", help="Where to write it (default: <PATH>/Dockerfile.hardened)"
    ),
    no_dockerignore: bool = typer.Option(
        False, "--no-dockerignore", help="Do not create a .dockerignore"
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file"),
) -> None:
    """Write a hardened Dockerfile into a project.

    Never replaces an existing Dockerfile: the generated file lands beside
    it as `Dockerfile.hardened` so the two can be diffed before switching.
    """
    generator = build_template_generator(build_hardening_level())
    try:
        result = generator.execute(
            Path(path),
            base=base,
            output=Path(output) if output else None,
            write_dockerignore=not no_dockerignore,
            force=force,
        )
    except TemplateGenerationError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from e

    verb = "Replaced" if result.overwritten else "Wrote"
    detected = " [dim](detected from your project)[/dim]" if result.detected_from else ""
    console.print(
        f"[green]{verb}[/green] {result.dockerfile_path} "
        f"from the [cyan]{result.template}[/cyan] template{detected}"
    )
    if result.dockerignore_path:
        console.print(f"[green]Wrote[/green] {result.dockerignore_path}")
    if result.checks_total:
        console.print(
            f"[dim]Validation: {result.checks_passed}/{result.checks_total} rules pass "
            f"out of the box.[/dim]"
        )
    console.print(
        "\n[dim]Review it, then build with:\n"
        f"  dockerls build {path} --file {result.dockerfile_path} --tag myapp:1.0 --scan[/dim]"
    )
