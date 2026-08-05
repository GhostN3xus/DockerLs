from __future__ import annotations

import asyncio

import httpx
from rich.console import Console
from rich.table import Table

console = Console()


def health() -> None:
    """Check connectivity to external services."""
    asyncio.run(_health())


async def _health() -> None:
    console.print("[bold]Service Health Check[/bold]\n")

    endpoints = {
        "Docker Hub API": "https://hub.docker.com/v2/",
        "endoflife.date": "https://endoflife.date/api/python.json",
        "NVD API": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
    }

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Service", style="bold")
    table.add_column("Status")

    async with httpx.AsyncClient(timeout=10) as client:
        for name, url in endpoints.items():
            try:
                resp = await client.get(url)
                if resp.status_code < 400:
                    table.add_row(name, f"[green]OK ({resp.status_code})[/green]")
                else:
                    table.add_row(name, f"[yellow]{resp.status_code}[/yellow]")
            except httpx.HTTPError as e:
                table.add_row(name, f"[red]Error: {e}[/red]")

    console.print(table)
