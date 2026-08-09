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
    output_format: str = typer.Option("cyclonedx", "--format", "-f", help="cyclonedx or spdx"),
    output: str = typer.Option("", "--output", "-o", help="Output file path (default: stdout)"),
) -> None:
    """Generate a Software Bill of Materials (SBOM) for an image via Trivy."""
    fmt = _FORMAT_ALIASES.get(output_format.lower())
    if fmt is None:
        console.print(
            f"[red]Unsupported SBOM format: {output_format}. Use cyclonedx or spdx.[/red]"
        )
        raise typer.Exit(1)
    try:
        asyncio.run(_sbom(image, fmt, output))
    except ValueError as e:
        # A malformed image reference is rejected by `sanitize_image_name`
        # inside the scanner; surfacing it as a message keeps `sbom` in line
        # with every other command.
        console.print(f"[red]Invalid image reference:[/red] {e}")
        raise typer.Exit(1) from e


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
        path = Path(output)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        except OSError as e:
            # An unwritable destination is user error, not a traceback.
            console.print(f"[red]Could not write {path}:[/red] {e}")
            raise typer.Exit(1) from e
        console.print(f"[green]SBOM written to {output}[/green]")
    else:
        console.print(content, soft_wrap=True)
