from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console

from dockerls.integrations.trivy.scanner import TrivyScanner

console = Console()

_FORMAT_ALIASES = {"cyclonedx": "cyclonedx", "spdx": "spdx-json", "spdx-json": "spdx-json"}


def sbom(
    image: str = typer.Argument(help="Full image reference (e.g., node:22-alpine)"),
    format: str = typer.Option("cyclonedx", "--format", "-f", help="cyclonedx or spdx"),
    output: str = typer.Option("", "--output", "-o", help="Output file path (default: stdout)"),
) -> None:
    """Generate a Software Bill of Materials (SBOM) for an image via Trivy."""
    fmt = _FORMAT_ALIASES.get(format.lower())
    if fmt is None:
        console.print(f"[red]Unsupported SBOM format: {format}. Use cyclonedx or spdx.[/red]")
        raise typer.Exit(1)
    asyncio.run(_sbom(image, fmt, output))


async def _sbom(image: str, fmt: str, output: str) -> None:
    scanner = TrivyScanner()
    if not await scanner.is_available():
        console.print("[red]Trivy is required for SBOM generation. Run `dockerls doctor`.[/red]")
        raise typer.Exit(1)

    content = await scanner.generate_sbom(image, fmt=fmt)
    if content is None:
        console.print(f"[red]Failed to generate SBOM for {image}[/red]")
        raise typer.Exit(1)

    if output:
        Path(output).write_text(content, encoding="utf-8")
        console.print(f"[green]SBOM written to {output}[/green]")
    else:
        console.print(content)
