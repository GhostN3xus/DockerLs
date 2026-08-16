"""Shared option types for the CLI.

Modelling the choice as a StrEnum keeps the accepted values in one place, so
a plain ``str`` compared with ``== "json"`` can no longer fall through to the
default branch on a typo like ``--format jsonn``.

The value is parsed in the command body rather than declared as a Typer enum
parameter on purpose. Typer rejects an unknown choice with **exit code 2**,
and 2 is not free in this CLI: ``recommend`` publishes it as "no image met
the baseline, but alternatives were found". A CI gate keying on the exit
code would read a typo in a flag as a security verdict. Parsing here keeps
usage errors on the shared operational code (1), which is what they are.
"""

from __future__ import annotations

from enum import StrEnum

import typer
from rich.console import Console

from dockerls.exit_codes import EXIT_ERROR

_console = Console()


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"


def parse_output_format(value: str) -> OutputFormat:
    """Resolve ``--format`` or fail with an actionable message and exit 1."""
    try:
        return OutputFormat(value)
    except ValueError as e:
        choices = ", ".join(f.value for f in OutputFormat)
        _console.print(
            f"[red]Error:[/red] unsupported --format {value!r}.\n"
            f"[dim]Suggested action: use one of: {choices}[/dim]"
        )
        raise typer.Exit(EXIT_ERROR) from e
