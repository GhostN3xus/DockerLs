"""Shared option types for the CLI.

Modelling choice options as StrEnums lets Typer reject invalid values before
the command body runs, the same way ``--fail-on`` already works. A plain
``str`` compared with ``== "json"`` silently falls through to the default
branch on a typo like ``--format jsonn``.
"""

from __future__ import annotations

from enum import StrEnum


class OutputFormat(StrEnum):
    TABLE = "table"
    JSON = "json"
