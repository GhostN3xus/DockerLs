"""`dockerls base` -- as bases do seu Dockerfile, conferidas contra o registry.

O `analyze-dockerfile` lia o seu projeto e não media nada; o `recommend` media
e nunca olhava o seu projeto. Este comando é a ponte: ele lê os `FROM`,
pergunta ao registry qual digest cada tag aponta **agora**, e diz quais bases
apodreceram.

Aplicar por padrão é escolha deliberada, e `--dry-run` existe para quem quer
ver antes. O motivo é o caso que este comando existe para pegar: uma base
fixada num digest velho não avisa ninguém, não quebra nada, e continua entrando
em produção build após build. Um comando que só relata delega ao esquecimento
exatamente o problema que o esquecimento causou.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING

import typer
from rich.console import Console

from dockerls.cli.dependencies import build_host_guard
from dockerls.cli.options import OutputFormat, parse_output_format
from dockerls.cli.text import safe
from dockerls.domain.value_objects.base_upgrade import BaseStatus
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY

if TYPE_CHECKING:
    from dockerls.application.use_cases.upgrade_base import UpgradeBaseResult

console = Console()

#: Cor por estado. `UNRESOLVED` é amarelo, não verde: não medir não é estar em
#: dia.
_COLORS = {
    BaseStatus.PINNED_CURRENT: "green",
    BaseStatus.PINNED_STALE: "red",
    BaseStatus.UNPINNED: "yellow",
    BaseStatus.UNRESOLVED: "yellow",
}


def base(
    path: str = typer.Argument(".", help="Diretório com Dockerfile, ou o próprio arquivo"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Mostra o que mudaria sem escrever no arquivo"
    ),
    output_format: str = typer.Option(
        OutputFormat.TABLE.value, "--format", "-f", help="Formato de saída: table ou json"
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Desativa cor na saída"),
) -> None:
    """Confere as bases do Dockerfile contra o registry e atualiza os digests."""
    if no_color:
        console.no_color = True
    fmt = parse_output_format(output_format)
    asyncio.run(_base(path, apply=not dry_run, output_format=fmt))


async def _base(path: str, *, apply: bool, output_format: OutputFormat) -> None:
    # Import tardio: montar o inspector puxa configuração e cliente HTTP, e o
    # `--help` deste comando não precisa de nada disso.
    from dockerls.application.use_cases.upgrade_base import UpgradeBaseUseCase
    from dockerls.integrations.registry.inspector import RegistryInspector

    inspector = RegistryInspector(guard=build_host_guard())
    try:
        result = await UpgradeBaseUseCase(inspector).execute(path, apply=apply)
    finally:
        await inspector.close()

    if output_format == OutputFormat.JSON:
        console.print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), soft_wrap=True)
    else:
        _render(result, apply=apply)

    if result.error:
        raise typer.Exit(EXIT_ERROR)
    # Reprova quando sobrou base desatualizada: em `--dry-run` isso é o portão
    # de CI, e depois de aplicar só sobra o que não deu para corrigir.
    raise typer.Exit(EXIT_POLICY if result.needs_action and not result.applied else EXIT_OK)


def _render(result: UpgradeBaseResult, *, apply: bool) -> None:
    if result.error:
        console.print(f"[red]Erro:[/red] {safe(result.error)}")
        return

    console.print(f"[bold]{safe(result.dockerfile)}[/bold]\n")
    for finding in result.findings:
        color = _COLORS.get(finding.status, "white")
        stage = f"  [dim](estágio {safe(finding.base.stage)})[/dim]" if finding.base.stage else ""
        console.print(
            f"  linha {finding.base.line}  [{color}]{finding.status}[/{color}]{stage}\n"
            f"    {safe(finding.base.reference)}"
        )
        console.print(f"    [dim]{safe(finding.explain())}[/dim]")
        if finding.proposed_reference:
            alvo = (
                f"ARG {safe(finding.base.digest_arg)}"
                if finding.base.digest_arg
                else f"linha {finding.base.line}"
            )
            console.print(
                f"    [green]->[/green] {safe(finding.proposed_reference)}  [dim]({alvo})[/dim]"
            )
        console.print()

    resumo = []
    if result.outdated:
        resumo.append(f"{len(result.outdated)} desatualizada(s)")
    if result.unpinned:
        resumo.append(f"{len(result.unpinned)} sem digest")
    if resumo:
        console.print(f"[bold]{', '.join(resumo)}[/bold]\n")

    if result.applied:
        console.print(
            f"[green]{result.applied} atualização(ões) escrita(s) em "
            f"{safe(result.dockerfile)}.[/green]"
        )
        console.print(
            "[dim]Reconstrua e escaneie antes de publicar: trocar o digest da base "
            "muda a imagem, e nada além de um scan diz se para melhor.[/dim]"
        )
    elif result.needs_action:
        acao = "Nada foi escrito (--dry-run)." if not apply else "Nada pôde ser escrito."
        console.print(f"[yellow]{acao}[/yellow]")
    else:
        console.print("[green]Todas as bases estão no digest que a tag aponta hoje.[/green]")

    if result.unresolved:
        console.print(
            f"[yellow]{len(result.unresolved)} base(s) não puderam ser consultadas no "
            "registry — isso é ausência de resposta, não confirmação de que estão em "
            "dia.[/yellow]"
        )
