from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.measure import Measurement
from rich.table import Table

from dockerls.cli.dependencies import build_analyze_use_case
from dockerls.exit_codes import EXIT_ERROR

console = Console()


def analyze(
    image: str = typer.Argument(help="Full image reference (e.g., node:22-alpine)"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
    wide: bool = typer.Option(
        False, "--wide", help="Render the table without truncating any column"
    ),
) -> None:
    """Deep-analyze a specific Docker image tag."""
    if no_color:
        console.no_color = True
    asyncio.run(_analyze(image, wide=wide))


# A CVE ID is the primary key of a finding: "CVE-2026…" identifies nothing and
# cannot be looked up. `CVE-YYYY-NNNNN` is 14 cells, so the column reserves
# that much and the flexible columns (package, versions) give up width first.
_CVE_MIN_WIDTH = 14

# Used to measure what the table would like to be, free of the terminal's
# width -- Measurement clamps to the console otherwise, which makes an
# overflowing table look like a table that fits.
_UNBOUNDED_WIDTH = 10_000


async def _analyze(image: str, wide: bool = False) -> None:
    use_case = await build_analyze_use_case()
    try:
        result = await use_case.execute(image)
    except ValueError as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        raise typer.Exit(EXIT_ERROR) from e

    console.print(f"\n[bold]Analysis: {result.image.full_reference}[/bold]\n")

    info = Table(show_header=False, box=None, padding=(0, 2))
    info.add_column("Key", style="bold")
    info.add_column("Value")
    info.add_row("Score", f"[green]{result.security_score}[/green]")
    info.add_row("Tier", result.tier)
    info.add_row("Critical", f"[red]{result.scan.critical_count}[/red]")
    info.add_row("High", f"[yellow]{result.scan.high_count}[/yellow]")
    info.add_row("Medium", str(result.scan.medium_count))
    info.add_row("Low", str(result.scan.low_count))
    info.add_row("Total Vulns", str(result.scan.total_count))
    info.add_row("Fixable", str(result.scan.fixable_count))
    info.add_row("Remediation Score", f"{result.remediation_score}%")
    info.add_row("EOL", "Yes" if result.is_eol else "No")
    info.add_row("LTS", "Yes" if result.is_lts else "No")
    info.add_row("Scanner", result.scan.scanner)
    console.print(info)

    if result.scan.vulnerabilities:
        console.print("\n[bold]Vulnerabilities[/bold]\n")
        vtable = Table()
        # `overflow="fold"` rather than the default ellipsis: a CVE ID that
        # somehow exceeds the reserved width wraps to a second line, still
        # readable, instead of being cut.
        vtable.add_column("CVE", style="cyan", min_width=_CVE_MIN_WIDTH, overflow="fold")
        vtable.add_column("Severity")
        vtable.add_column("CVSS", justify="right")
        # `ratio` marks these three as the flexible ones: when the terminal is
        # too narrow, they are what shrinks.
        vtable.add_column("Package", overflow="ellipsis", ratio=1)
        vtable.add_column("Installed", overflow="ellipsis", ratio=1)
        vtable.add_column("Fixed", overflow="ellipsis", ratio=1)
        vtable.add_column("Status")

        sev_styles = {
            "CRITICAL": "bold red",
            "HIGH": "yellow",
            "MEDIUM": "white",
            "LOW": "dim",
        }
        for v in sorted(
            result.scan.vulnerabilities,
            key=lambda x: x.cvss_score,
            reverse=True,
        )[:30]:
            st = sev_styles.get(v.severity.value, "")
            status = "FIX AVAILABLE" if v.is_fixable else "NO FIX"
            status_style = "green" if v.is_fixable else "red"
            vtable.add_row(
                v.cve_id,
                f"[{st}]{v.severity.value}[/{st}]" if st else v.severity.value,
                f"{v.cvss_score:.1f}",
                v.package_name,
                v.installed_version,
                v.fixed_version or "-",
                f"[{status_style}]{status}[/{status_style}]",
            )
        _print_vulnerabilities(vtable, wide)


def _print_vulnerabilities(vtable: Table, wide: bool) -> None:
    """Render the findings table, never at the cost of a CVE ID.

    Rich only redistributes width among columns marked flexible, and only
    when the table is told to fill the available width. Left alone, a table
    wider than the terminal is cropped on the right instead -- which is how
    the CVE column ended up truncated and the last column lost its border.
    """
    natural_width = Measurement.get(
        console, console.options.update(max_width=_UNBOUNDED_WIDTH), vtable
    ).maximum

    if wide:
        # Give the table exactly the width it asked for: nothing truncates.
        Console(width=natural_width, no_color=console.no_color).print(vtable)
        return

    # Only fit-to-width when the terminal is too narrow. On a wide terminal
    # the table keeps its natural layout rather than being stretched.
    vtable.expand = natural_width > console.width
    console.print(vtable)
