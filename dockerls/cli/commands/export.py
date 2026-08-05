from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console

from dockerls.cli.dependencies import build_recommend_use_case
from dockerls.exporters.factory import ExporterFactory

console = Console()


def export(
    image: str = typer.Argument(help="Docker image name"),
    format: str = typer.Option("json", "--format", "-f", help="Export format: json, csv, html, markdown"),
    output: str = typer.Option("", "--output", "-o", help="Output file path (default: stdout)"),
    workers: int = typer.Option(10, "--workers", "-w", help="Concurrent workers"),
) -> None:
    """Export analysis results in various formats."""
    asyncio.run(_export(image, format, output, workers))


async def _export(image: str, fmt: str, output: str, workers: int) -> None:
    use_case = await build_recommend_use_case(workers=workers)
    result = await use_case.execute(image)

    try:
        exporter = ExporterFactory.create(fmt)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    if output:
        path = Path(output)
        exporter.export(result, path)
        console.print(f"[green]Report exported to {path}[/green]")
    else:
        console.print(exporter.export_string(result))
