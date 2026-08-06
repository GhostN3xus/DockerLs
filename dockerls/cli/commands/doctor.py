from __future__ import annotations

import asyncio
import shutil

from rich.console import Console
from rich.table import Table

console = Console()


def doctor() -> None:
    """Check system dependencies and configuration."""
    asyncio.run(_doctor())


async def _doctor() -> None:
    console.print("[bold]DockerLs System Check[/bold]\n")

    checks = Table(show_header=False, box=None, padding=(0, 2))
    checks.add_column("Component", style="bold")
    checks.add_column("Status")

    tools = {
        "trivy": "Primary vulnerability scanner",
        "grype": "Fallback vulnerability scanner",
    }

    all_ok = True
    for tool, desc in tools.items():
        available = shutil.which(tool) is not None
        status = "[green]Available[/green]" if available else "[yellow]Not found[/yellow]"
        checks.add_row(f"{tool} ({desc})", status)
        if tool == "trivy" and not available:
            all_ok = False

    try:
        import httpx  # noqa: F401

        checks.add_row("httpx", "[green]Available[/green]")
    except ImportError:
        checks.add_row("httpx", "[red]Missing[/red]")
        all_ok = False

    try:
        import keyring  # noqa: F401

        checks.add_row("keyring", "[green]Available[/green]")
    except ImportError:
        checks.add_row("keyring", "[yellow]Not installed (optional)[/yellow]")

    console.print(checks)

    if all_ok:
        console.print("\n[green]All required components are available.[/green]")
    else:
        console.print(
            "\n[yellow]Some components are missing. Install Trivy for full functionality.[/yellow]"
        )
