from __future__ import annotations

import asyncio
import shutil

import typer
from rich.console import Console
from rich.table import Table

from dockerls.exit_codes import EXIT_ERROR, EXIT_OK

console = Console()

TRIVY_INSTALL_URL = "https://aquasecurity.github.io/trivy"
GRYPE_INSTALL_URL = "https://github.com/anchore/grype"


def doctor() -> None:
    """Check system dependencies and configuration."""
    # `doctor` is the documented way for a pipeline to check its
    # prerequisites before a scan job, so it has to *gate*: it used to print
    # "Some components are missing" and exit 0 anyway, which meant a runner
    # with no Trivy installed sailed past the check and failed later, in the
    # scan, where the cause is far less obvious. `health` already gates the
    # same way for network dependencies.
    raise typer.Exit(asyncio.run(_doctor()))


async def _doctor() -> int:
    console.print("[bold]DockerLs System Check[/bold]\n")

    checks = Table(show_header=False, box=None, padding=(0, 2))
    checks.add_column("Component", style="bold")
    checks.add_column("Status")

    has_trivy = shutil.which("trivy") is not None
    has_grype = shutil.which("grype") is not None

    for tool, desc, available in (
        ("trivy", "Primary vulnerability scanner", has_trivy),
        ("grype", "Fallback scanner / cross-validation", has_grype),
    ):
        status = "[green]Available[/green]" if available else "[yellow]Not found[/yellow]"
        checks.add_row(f"{tool} ({desc})", status)

    has_httpx = True
    try:
        import httpx  # noqa: F401

        checks.add_row("httpx", "[green]Available[/green]")
    except ImportError:  # pragma: no cover - httpx is a hard dependency
        checks.add_row("httpx", "[red]Missing[/red]")
        has_httpx = False

    try:
        import keyring  # noqa: F401

        checks.add_row("keyring", "[green]Available[/green]")
    except ImportError:
        checks.add_row("keyring", "[yellow]Not installed (optional)[/yellow]")

    console.print(checks)

    # The requirement is *a* scanner, not Trivy specifically: `ScannerFactory`
    # runs on Grype alone. Flagging a Grype-only machine as broken would have
    # been a false alarm, and flagging a machine with neither as fine was the
    # real failure.
    if has_httpx and (has_trivy or has_grype):
        if not (has_trivy and has_grype):
            console.print(
                "\n[yellow]Only one scanner is installed.[/yellow] "
                "[dim]Cross-validation needs both, so scores will be reported "
                "unconfirmed by a second tool.[/dim]"
            )
        else:
            console.print("\n[green]All required components are available.[/green]")
        return EXIT_OK

    console.print("\n[red]DockerLs cannot measure anything on this machine.[/red]")
    console.print("\n[bold]Cause[/bold]")
    if not (has_trivy or has_grype):
        console.print("  No vulnerability scanner is installed (needs Trivy or Grype).")
    if not has_httpx:  # pragma: no cover - httpx is a hard dependency
        console.print("  The httpx package is missing; reinstall dockerls.")

    console.print("\n[bold]Suggested action[/bold]")
    if not (has_trivy or has_grype):
        console.print(f"  Install Trivy:  [cyan]{TRIVY_INSTALL_URL}[/cyan]")
        console.print(f"  or install Grype: [cyan]{GRYPE_INSTALL_URL}[/cyan]")
    console.print(
        "\n[dim]Without a scanner, `recommend`, `analyze` and `advisor` report "
        "every tag as unverified rather than as safe.[/dim]"
    )
    return EXIT_ERROR
