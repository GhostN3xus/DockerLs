from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from dockerls.cli.dependencies import build_compare_use_case
from dockerls.cli.progress import scan_status
from dockerls.cli.run_options import RunOptions, parse_run_options
from dockerls.cli.scan_failure import describe_scan_failure
from dockerls.cli.text import safe
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, exit_code_for_completeness
from dockerls.utils.deadline import Deadline

if TYPE_CHECKING:
    from dockerls.application.dto.analysis import ComparisonResult, UnverifiedImage

console = Console()

# Exit codes, em ordem de severidade:
#   0 = comparação completa: toda imagem pedida foi escaneada
#   1 = erro rígido: uso inválido, ou nenhuma imagem pôde ser escaneada
#   2 = comparação parcial: 2+ escanearam, 1+ falharam
#   3 = dado insuficiente: menos de duas imagens escaneadas, nada a comparar
# 0 e 1 vêm do contrato compartilhado; 2 e 3 são próprios de `compare` --
# a diferença entre "comparei tudo" e "comparei o que deu" é justamente o
# que um portão de CI precisa poder distinguir.
EXIT_COMPLETE = EXIT_OK
EXIT_ERROR_CODE = EXIT_ERROR
EXIT_PARTIAL = 2
EXIT_INSUFFICIENT = 3


def compare(
    images: list[str] = typer.Argument(help="Two or more image references to compare"),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
    platform: str | None = typer.Option(
        None,
        "--platform",
        help="os/architecture, with an optional /variant, e.g. linux/arm64 (default: linux/amd64)",
    ),
    time_budget: float | None = typer.Option(
        None,
        "--time-budget",
        help=(
            "Total seconds for the whole comparison. Images not measured in time are "
            "reported as not measured and the comparison is PARTIAL (exit 5)"
        ),
    ),
) -> None:
    """Compare security posture of multiple Docker images.

    Exit codes: 0 = every image was scanned and compared; 1 = invalid use, or
    no image could be scanned at all; 2 = partial comparison, at least two
    images were scanned and at least one failed; 3 = fewer than two images
    could be scanned, so there is nothing to compare.

    An image that could not be scanned is never given a score or a tier: it
    is listed separately, with the classified reason.

    With --time-budget the whole comparison is bounded. Images the budget cut
    off are listed as not measured and the exit code is 5 (some measured) or 4
    (none): a comparison cut short is never presented as a complete one.
    """
    if no_color:
        console.no_color = True
    if len(images) < 2:
        console.print("[red]Provide at least two images to compare.[/red]")
        raise typer.Exit(EXIT_ERROR_CODE)
    options = parse_run_options(platform=platform, time_budget=time_budget)
    asyncio.run(_compare(images, options))


async def _compare(images: list[str], options: RunOptions | None = None) -> None:
    options = options or parse_run_options()
    deadline = Deadline(options.time_budget) if options.time_budget else Deadline.unbounded()
    use_case = await build_compare_use_case(
        len(images), platform=options.platform, deadline=deadline
    )
    try:
        with scan_status(f"Scanning {len(images)} image(s) to compare..."):
            result = await use_case.execute(images)
    except ValueError as e:
        console.print(f"[red]Scan failed: {e}[/red]")
        raise typer.Exit(EXIT_ERROR_CODE) from e

    # `result.images` já chega filtrado pelo use case: só entra aqui quem
    # tem scan verificado. A tabela abaixo, portanto, não tem como exibir
    # um score que ninguém mediu.
    measured = result.images
    # Images the *clock* cut off are a different thing from images that failed:
    # they were never attempted, and they make the whole comparison partial.
    out_of_time = [u for u in result.unverified if u.kind == "DEADLINE_EXCEEDED"]
    completeness = ("PARTIAL" if measured else "NO_RESULT") if out_of_time else "COMPLETE"

    if not measured:
        # Nada foi medido. Não é um veredito sobre as imagens -- é a
        # ausência de um --, e o código 1 diz isso: falha de execução.
        _print_failures(result)
        console.print(
            "\n[bold red]No image could be scanned.[/bold red]\n"
            "[dim]This is a technical failure, not a security verdict: nothing was "
            "measured, so nothing can be said about these images.[/dim]"
        )
        raise typer.Exit(exit_code_for_completeness(EXIT_ERROR_CODE, completeness))

    if len(measured) < 2:
        # Uma imagem medida não é uma comparação. Mostrar a tabela com uma
        # linha só sugeriria um vencedor onde não houve disputa.
        _print_failures(result)
        console.print(
            f"\n[bold yellow]Not enough data to compare.[/bold yellow]\n"
            f"[yellow]Only {safe(measured[0].image.full_reference)} could be scanned; "
            f"a comparison needs at least two.[/yellow]"
        )
        raise typer.Exit(exit_code_for_completeness(EXIT_INSUFFICIENT, completeness))

    console.print(
        Panel(f"[bold]Image Comparison[/bold] [dim]({options.platform})[/dim]", expand=False)
    )

    table = Table()
    table.add_column("Image", style="cyan")
    table.add_column("Score", justify="right", style="green")
    table.add_column("Tier", justify="center")
    table.add_column("Critical", justify="right", style="red")
    table.add_column("High", justify="right", style="yellow")
    table.add_column("Medium", justify="right")
    table.add_column("Total Vulns", justify="right")
    table.add_column("Fixable", justify="right")
    table.add_column("Remediation", justify="right")

    for a in measured:
        table.add_row(
            safe(a.image.full_reference),
            # A score is never shown without its blockers: `*` marks an image
            # the readiness policy blocks, whatever its number says.
            f"{a.security_score}{'*' if a.readiness_blockers else ''}",
            a.tier,
            str(a.scan.critical_count),
            str(a.scan.high_count),
            str(a.scan.medium_count),
            str(a.scan.total_count),
            str(a.scan.fixable_count),
            f"{a.remediation_score}/100",
        )
    console.print(table)
    if any(a.readiness_blockers for a in measured):
        console.print(
            "[dim]* = blocked by the production-readiness policy "
            "(see `dockerls analyze` for the reasons)[/dim]"
        )

    _print_verdict(result)
    _print_failures(result)
    _print_not_measured(out_of_time)

    if out_of_time:
        console.print(
            f"\n[bold yellow]Partial comparison:[/bold yellow] the time budget ended with "
            f"{len(measured)} of {len(measured) + len(result.unverified)} image(s) measured. "
            "This is not a complete comparison."
        )
        raise typer.Exit(exit_code_for_completeness(EXIT_PARTIAL, completeness))
    if result.unverified:
        console.print(
            f"\n[dim]Partial comparison: {len(measured)} of "
            f"{len(measured) + len(result.unverified)} image(s) were measured.[/dim]"
        )
        raise typer.Exit(EXIT_PARTIAL)
    raise typer.Exit(EXIT_COMPLETE)


def _print_not_measured(items: list[UnverifiedImage]) -> None:
    """Images the time budget cut off: not failed, not attempted."""
    if not items:
        return
    console.print("\n[bold cyan]Not measured (time budget)[/bold cyan]")
    console.print(
        "[dim]  These images were not compared: the budget ended before they were scanned. "
        "That says nothing about them.[/dim]"
    )
    for item in items:
        console.print(f"  {safe(item.image_reference)}")


def _print_failures(result: ComparisonResult) -> None:
    """As imagens que não puderam ser medidas, com a causa classificada.

    Seção própria, e nunca uma linha na tabela: o leitor precisa ver de
    imediato que estas não foram comparadas com as outras, e sim deixadas
    de fora por falta de medição.
    """
    failed = [u for u in result.unverified if u.kind != "DEADLINE_EXCEEDED"]
    if not failed:
        return
    console.print("\n[bold yellow]Failed (not compared)[/bold yellow]")
    console.print("[dim]  These images were never scored -- no successful scan.[/dim]")
    for item in failed:
        console.print(
            f"  {safe(item.image_reference)}  "
            f"[dim]{safe(describe_scan_failure(item.kind, item.reason))}[/dim]"
        )


def _print_verdict(result: ComparisonResult) -> None:
    """Vencedor primeiro, depois cada perdedor com o próprio delta.

    A versão anterior juntava tudo numa linha -- vencedor, score absoluto e
    diferença separados por ponto e vírgula --, e o `-36.0 points` do final
    lia como um score negativo em vez de uma distância até o vencedor.
    """
    winner = next((a for a in result.images if a.image.full_reference == result.winner), None)
    if winner is None:
        return

    console.print(
        f"\n[bold green]Winner: {safe(winner.image.full_reference)}[/bold green] "
        f"[dim](Score {winner.security_score}, Tier {winner.tier})[/dim]"
    )
    for a in result.images:
        if a.image.full_reference == result.winner:
            continue
        delta = a.security_score - winner.security_score
        console.print(
            f"  {safe(a.image.full_reference)}  Score {a.security_score}, Tier {a.tier}  "
            f"[dim]({delta:+.1f} vs. winner)[/dim]"
        )

    if result.common_vulns:
        console.print(f"\n[bold]Shared vulnerabilities:[/bold] {len(result.common_vulns)}")
    for reference, vulns in result.unique_vulns.items():
        if vulns:
            console.print(f"[dim]Unique to {safe(reference)}: {len(vulns)}[/dim]")
