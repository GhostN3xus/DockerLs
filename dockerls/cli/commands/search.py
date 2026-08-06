from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.table import Table

from dockerls.cli.dependencies import build_search_use_case

console = Console()


def search(
    image: str = typer.Argument(help="Docker image name (e.g., node, python, nginx)"),
    limit: int = typer.Option(100, "--limit", "-l", help="Maximum tags to retrieve"),
) -> None:
    """Search Docker Hub for available tags of an image."""
    asyncio.run(_search(image, limit))


async def _search(image: str, limit: int) -> None:
    use_case = await build_search_use_case()
    tags = await use_case.execute(image, limit=limit)

    if not tags:
        console.print(f"[red]No tags found for '{image}'[/red]")
        raise typer.Exit(1)

    table = Table(title=f"Tags for {image}")
    table.add_column("Tag", style="cyan")
    table.add_column("Size (MB)", justify="right")
    table.add_column("Architecture")
    table.add_column("Last Updated")
    table.add_column("Official", justify="center")

    for tag in tags:
        size_mb = f"{tag.size_bytes / (1024 * 1024):.1f}" if tag.size_bytes else "-"
        updated = tag.last_updated.strftime("%Y-%m-%d") if tag.last_updated else "-"
        official = "Yes" if tag.is_official else "No"
        table.add_row(tag.tag, size_mb, tag.architecture, updated, official)

    console.print(table)
    console.print(f"\n[dim]Total: {len(tags)} tags[/dim]")
