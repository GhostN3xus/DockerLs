from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import typer
from rich.console import Console
from sqlalchemy.exc import SQLAlchemyError

from dockerls.cli.dependencies import build_cache

if TYPE_CHECKING:
    from collections.abc import Coroutine

console = Console()
cache_app = typer.Typer(help="Manage the scan cache")

EXIT_ERROR = 1


def _run(coro: Coroutine[Any, Any, None]) -> None:
    """Run a cache operation, reporting storage failures as user errors.

    A corrupt or unreadable cache database is a normal operational state --
    it must not exit with a traceback, especially for `clear`, which is
    exactly what a user reaches for when the cache is broken.
    """
    try:
        asyncio.run(coro)
    except (OSError, SQLAlchemyError) as e:
        console.print(f"[red]Cache operation failed:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e


@cache_app.command("clear")
def cache_clear() -> None:
    """Clear all cached scan results."""
    _run(_clear())


async def _clear() -> None:
    cache = build_cache()
    await cache.clear()
    console.print("[green]Cache cleared.[/green]")


@cache_app.command("cleanup")
def cache_cleanup() -> None:
    """Remove expired cache entries."""
    _run(_cleanup())


async def _cleanup() -> None:
    cache = build_cache()
    count = await cache.cleanup_expired()
    console.print(f"[green]Removed {count} expired entries.[/green]")
