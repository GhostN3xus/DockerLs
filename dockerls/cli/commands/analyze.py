from __future__ import annotations

import asyncio

import typer
from rich.console import Console
from rich.table import Table

from dockerls.cli.dependencies import build_analyze_use_case

console = Console()


def analyze(
    image: str = typer.Argument(help="Full image reference (e.g., node:22-alpine)"),
) -> None:
    """Deep-analyze a specific Docker image tag."""
    asyncio.run(_analyze(image))


async def _analyze(image: str) -> None:
    use_case = await build_analyze_use_case()
    try:
        result = await use_case.execute(image)
    except ValueError as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        raise typer.Exit(1) from e

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
        vtable.add_column("CVE", style="cyan")
        vtable.add_column("Severity")
        vtable.add_column("CVSS", justify="right")
        vtable.add_column("Package")
        vtable.add_column("Installed")
        vtable.add_column("Fixed")
        vtable.add_column("Status")

        sev_styles = {
            "CRITICAL": "bold red", "HIGH": "yellow",
            "MEDIUM": "white", "LOW": "dim",
        }
        for v in sorted(
            result.scan.vulnerabilities,
            key=lambda x: x.cvss_score, reverse=True,
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
        console.print(vtable)
