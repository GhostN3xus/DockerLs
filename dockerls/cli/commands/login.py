from __future__ import annotations

import typer
from rich.console import Console

from dockerls.utils.auth import store_credentials

console = Console()


def login(
    username: str = typer.Option("", "--username", "-u", prompt="Docker Hub username"),
    token: str = typer.Option("", "--token", "-t", prompt="Docker Hub token", hide_input=True),
) -> None:
    """Authenticate with Docker Hub. Credentials are stored in your system keyring."""
    if not username or not token:
        console.print("[red]Username and token are required.[/red]")
        raise typer.Exit(1)

    if store_credentials(username, token):
        console.print("[green]Credentials stored securely in keyring.[/green]")
    else:
        console.print(
            "[yellow]Keyring not available. Set DOCKERHUB_USERNAME and "
            "DOCKERHUB_TOKEN environment variables instead.[/yellow]"
        )
