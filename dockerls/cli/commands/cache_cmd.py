from __future__ import annotations

import asyncio

import typer
from rich.console import Console

from dockerls.cli.dependencies import build_cache

console = Console()
cache_app = typer.Typer(help="Manage the scan cache")


@cache_app.command("clear")
def cache_clear() -> None:
    """Clear all cached scan results."""
    asyncio.run(_clear())


async def _clear() -> None:
    cache = build_cache()
    await cache.clear()
    console.print("[green]Cache cleared.[/green]")


@cache_app.command("cleanup")
def cache_cleanup() -> None:
    """Remove expired cache entries."""
    asyncio.run(_cleanup())


async def _cleanup() -> None:
    cache = build_cache()
    count = await cache.cleanup_expired()
    console.print(f"[green]Removed {count} expired entries.[/green]")
