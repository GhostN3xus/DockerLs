from __future__ import annotations

from rich.console import Console

from dockerls import __version__

console = Console()


def version() -> None:
    """Show DockerLs version."""
    console.print(f"DockerLs v{__version__}")
