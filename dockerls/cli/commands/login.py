from __future__ import annotations

import asyncio

import typer
from rich.console import Console

from dockerls.exit_codes import EXIT_ERROR
from dockerls.integrations.dockerhub.client import DockerHubClient
from dockerls.utils.auth import clear_credentials, store_credentials

console = Console()


def login(
    username: str = typer.Option("", "--username", "-u", prompt="Docker Hub username"),
    token: str = typer.Option("", "--token", "-t", prompt="Docker Hub token", hide_input=True),
) -> None:
    """Authenticate with Docker Hub. Credentials are stored in your system keyring."""
    if not username or not token:
        console.print("[red]Username and token are required.[/red]")
        raise typer.Exit(EXIT_ERROR)

    asyncio.run(_login(username, token))


async def _login(username: str, token: str) -> None:
    client = DockerHubClient(username=username, token=token)
    if not await client.authenticate():
        console.print("[red]Authentication failed. Check your username and token.[/red]")
        raise typer.Exit(EXIT_ERROR)

    if store_credentials(username, token):
        console.print("[green]Authenticated. Credentials stored securely in keyring.[/green]")
    else:
        console.print(
            "[yellow]Authenticated, but keyring is not available. Set "
            "DOCKERHUB_USERNAME and DOCKERHUB_TOKEN environment variables "
            "to persist credentials instead.[/yellow]"
        )


def logout() -> None:
    """Remove stored Docker Hub credentials.

    `login` could store credentials with no supported way to remove them,
    which left `clear_credentials` implemented and unreachable.
    """
    if clear_credentials():
        console.print("[green]Stored credentials removed.[/green]")
        return
    console.print("[yellow]No stored credentials to remove.[/yellow]")
    raise typer.Exit(EXIT_ERROR)
