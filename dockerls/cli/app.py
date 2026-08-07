from __future__ import annotations

import typer

from dockerls.cli.commands.advisor import advisor
from dockerls.cli.commands.analyze import analyze
from dockerls.cli.commands.cache_cmd import cache_app
from dockerls.cli.commands.compare import compare
from dockerls.cli.commands.doctor import doctor
from dockerls.cli.commands.export import export
from dockerls.cli.commands.health import health
from dockerls.cli.commands.login import login, logout
from dockerls.cli.commands.recommend import recommend
from dockerls.cli.commands.sbom import sbom
from dockerls.cli.commands.search import search
from dockerls.cli.commands.version import version

app = typer.Typer(
    name="dockerls",
    help="DockerLs -- Enterprise Docker Image Security Advisor. "
    "Discover the most secure Docker images available on Docker Hub.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)

app.command()(search)
app.command()(recommend)
app.command()(advisor)
app.command()(analyze)
app.command()(compare)
app.command()(export)
app.command()(login)
app.command()(logout)
app.command()(version)
app.command()(doctor)
app.command()(health)
app.command()(sbom)
app.add_typer(cache_app, name="cache", help="Manage scan cache")


def main() -> None:
    app()
