"""Render a `RunDiff`: what changed since the previous run, and why."""

from __future__ import annotations

from typing import TYPE_CHECKING

from dockerls.application.services.run_diff import Cause
from dockerls.cli.text import safe

if TYPE_CHECKING:
    from rich.console import Console

    from dockerls.application.services.run_diff import RunDiff

_CAUSE_TEXT = {
    Cause.IMAGE_CHANGED: "the image changed (the tag now names different bytes)",
    Cause.SCANNER_DATABASE_CHANGED: "same image; the scanner's database changed",
    Cause.IMAGE_AND_DATABASE_CHANGED: "the image and the scanner's database both changed",
    Cause.UNEXPLAINED: "not explained by the image or the database",
    Cause.NO_CHANGE: "no change",
    Cause.NOT_COMPARABLE: "not comparable",
}

_SHOWN = 8


def print_run_diff(console: Console, diff: RunDiff) -> None:
    console.print("\n[bold]Since the previous run[/bold]")
    if not diff.compatible or not diff.images:
        console.print(f"  [dim]{safe(diff.note) or 'nothing to compare'}[/dim]")
        return
    console.print(
        f"  [dim]compared with run {safe(diff.previous_run_id)} "
        f"({safe(diff.previous_created_at)})[/dim]"
    )
    for entry in diff.images:
        console.print(f"  [cyan]{safe(entry.reference)}[/cyan]: {_CAUSE_TEXT[entry.cause]}")
        if entry.note:
            console.print(f"    [dim]{safe(entry.note)}[/dim]")
        for label, findings, style in (
            ("new", entry.new, "red"),
            ("gone", entry.removed, "green"),
        ):
            if not findings:
                continue
            console.print(f"    [{style}]{label} ({len(findings)})[/{style}]")
            for finding in findings[:_SHOWN]:
                console.print(
                    f"      {safe(finding.cve_id)} {safe(finding.severity)} "
                    f"{safe(finding.package)} {safe(finding.installed_version)}"
                )
            if len(findings) > _SHOWN:
                console.print(f"      [dim]... and {len(findings) - _SHOWN} more[/dim]")
