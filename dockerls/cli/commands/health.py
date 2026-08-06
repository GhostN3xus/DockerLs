from __future__ import annotations

import asyncio

import httpx
import typer
from rich.console import Console
from rich.table import Table

console = Console()

# Exit codes so `health` is usable as a CI gate.
EXIT_HEALTHY = 0
EXIT_DEGRADED = 1

# Each probe must be an endpoint the tool actually depends on *and* one that
# answers 2xx when healthy. `https://hub.docker.com/v2/` was neither: it
# returns 404 by design, so every single run reported the Hub as degraded.
# The list tracks the real dependencies -- the image catalogues that feed
# the scan pipeline and the threat-intel feeds that weight the score.
ENDPOINTS = {
    "Docker Hub API": "https://hub.docker.com/v2/repositories/library/node/",
    "Chainguard (cgr.dev)": "https://cgr.dev/token?scope=repository:chainguard/node:pull&service=cgr.dev",
    "Distroless (gcr.io)": "https://gcr.io/v2/distroless/base/tags/list",
    "endoflife.date": "https://endoflife.date/api/python.json",
    "CISA KEV": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "EPSS (FIRST)": "https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
}


def health() -> None:
    """Check connectivity to external services."""
    raise typer.Exit(asyncio.run(_health()))


async def _health() -> int:
    console.print("[bold]Service Health Check[/bold]\n")

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Service", style="bold")
    table.add_column("Status")

    degraded = False
    async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
        for name, url in ENDPOINTS.items():
            try:
                resp = await client.get(url)
            except httpx.HTTPError as e:
                # Unreachable is a failure, not a curiosity: DNS, TLS,
                # proxy and timeout errors all land here.
                table.add_row(name, f"[red]Unreachable: {type(e).__name__}[/red]")
                degraded = True
                continue

            if resp.status_code < 400:
                table.add_row(name, f"[green]OK ({resp.status_code})[/green]")
            else:
                table.add_row(name, f"[red]HTTP {resp.status_code}[/red]")
                degraded = True

    console.print(table)
    if degraded:
        console.print("\n[yellow]One or more services are degraded.[/yellow]")
        return EXIT_DEGRADED
    console.print("\n[green]All services reachable.[/green]")
    return EXIT_HEALTHY
