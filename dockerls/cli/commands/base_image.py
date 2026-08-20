"""`dockerls base-image` -- gerar e construir a imagem base, item a item.

Uma imagem base é o piso de tudo que vem depois: cada pacote marcado aqui
existe em toda aplicação que a consome, e toda CVE dele vira triagem para
times que nem sabem que ele está lá. Por isso a escolha é uma tela em vez de
um Dockerfile copiado de outro projeto -- e por isso cada item aparece com o
que serve **e** o que custa, na hora de marcar e não depois.

O menu é curto de propósito. Uma lista com tudo que a distribuição publica
faria as pessoas marcarem tudo "por via das dúvidas", que é exatamente o
resultado que uma imagem base não pode ter.

A base sai fixada por digest sempre que o registry responder: uma imagem base
com tag móvel propaga a mesma incerteza para cada projeto que a consome, o que
é o oposto do que ela existe para fazer.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.prompt import Prompt

from dockerls.cli.dependencies import build_host_guard
from dockerls.cli.text import safe
from dockerls.domain.value_objects.base_recipe import (
    PACKAGE_CATALOG,
    REFUSED_PACKAGES,
    BaseRecipe,
    OsFamily,
    Runtime,
    UnsupportedCombinationError,
    render,
)
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK

console = Console()


def base_image(
    output: str = typer.Option(
        "Dockerfile", "--output", "-o", help="Onde escrever o Dockerfile gerado"
    ),
    os_family: str | None = typer.Option(None, "--os", help="alpine, debian, ubuntu ou distroless"),
    runtime: str | None = typer.Option(None, "--runtime", help="none, java, node, python ou go"),
    with_packages: str | None = typer.Option(
        None, "--with", help="Pacotes separados por vírgula, sem menu (para pipeline)"
    ),
    owner: str | None = typer.Option(None, "--owner", help="Time ou pessoa responsável"),
    source_url: str | None = typer.Option(None, "--source", help="URL do repositório"),
    title: str | None = typer.Option(None, "--title", help="Nome da imagem nos rótulos"),
    keep_manager: bool = typer.Option(
        False,
        "--keep-manager",
        help=(
            "Mantém o gerenciador de pacotes que a imagem oficial embute (npm, yarn). "
            "Por padrão ele é removido: numa base de execução, as dependências que ele "
            "carrega dentro de si são superfície pura e ficam fora do apk/apt"
        ),
    ),
    no_pin: bool = typer.Option(
        False, "--no-pin", help="Não resolver o digest da base (deixa a tag móvel)"
    ),
    force: bool = typer.Option(False, "--force", help="Sobrescreve o arquivo de saída"),
) -> None:
    """Gera o Dockerfile de uma imagem base a partir de um menu de escolhas."""
    try:
        family = _resolve_family(os_family)
        chosen_runtime = _resolve_runtime(runtime, family)
        packages = _resolve_packages(with_packages, family)
    except UnsupportedCombinationError as e:
        console.print(f"[red]Erro:[/red] {safe(str(e))}")
        raise typer.Exit(EXIT_ERROR) from e

    strip = _resolve_strip(chosen_runtime, family, keep_manager=keep_manager)
    recipe = BaseRecipe(
        family=family,
        runtime=chosen_runtime,
        packages=tuple(packages),
        strip_bundled_manager=strip,
        title=title or _default_title(family, chosen_runtime),
        description=_default_description(family, chosen_runtime),
        owner=(owner or "").strip(),
        source=(source_url or "").strip(),
    )

    if not no_pin:
        digest = asyncio.run(_resolve_digest(recipe))
        if digest:
            recipe = BaseRecipe(**{**recipe.__dict__, "digest": digest})
        else:
            console.print(
                "[yellow]O registry não respondeu qual digest a tag aponta.[/yellow]\n"
                "[dim]O Dockerfile sai sem digest e diz isso em voz alta -- uma imagem "
                "base com tag móvel propaga a incerteza para todo projeto que a "
                "consome.[/dim]"
            )

    try:
        content = render(recipe)
    except UnsupportedCombinationError as e:
        console.print(f"[red]Erro:[/red] {safe(str(e))}")
        raise typer.Exit(EXIT_ERROR) from e

    destination = Path(output)
    if destination.exists() and not force:
        console.print(
            f"[red]Erro:[/red] {destination} já existe. Use --force para sobrescrever "
            "ou --output para escrever em outro lugar."
        )
        raise typer.Exit(EXIT_ERROR)

    destination.write_text(content, encoding="utf-8")
    console.print(f"\n[green]Dockerfile escrito em {safe(str(destination))}.[/green]")
    console.print(
        "\n[bold]Próximo passo[/bold]\n"
        f"  [dim]dockerls build -t {safe(recipe.title)}:1.0 --fail-on critical "
        f"{safe(str(destination.parent))}[/dim]\n"
        "  [dim]Construir e escanear é o que transforma esta receita numa "
        "afirmação sobre segurança; até lá ela é só uma intenção.[/dim]"
    )
    raise typer.Exit(EXIT_OK)


def _resolve_strip(runtime: Runtime, family: OsFamily, *, keep_manager: bool) -> bool:
    """Se o gerenciador embutido sai da imagem.

    Isto virou opção por um caso medido: uma `node:22-alpine` recém-construída
    reportava 1 CRITICAL e 7 HIGH, e **todas** vinham das dependências que o
    npm carrega dentro de `node_modules` -- fora do alcance do `apk upgrade`,
    porque não são pacotes da distribuição. As camadas geradas por este comando
    reportavam zero.

    O padrão é remover, porque a pergunta certa numa base de *execução* é o que
    justifica manter: as dependências da aplicação são instaladas no estágio de
    build de quem consome, e nada aqui precisa instalar nada. Quem tem um
    `npm start` que resolve pacotes na subida passa `--keep-manager`.
    """
    from dockerls.domain.value_objects.base_recipe import RUNTIME_BASES

    base = RUNTIME_BASES.get((runtime, family))
    if base is None or not base.bundled_manager:
        return False
    if keep_manager:
        console.print(
            f"\n[yellow]{base.bundled_manager_note} ficam na imagem.[/yellow]\n"
            "[dim]As dependências que eles carregam dentro de si costumam ser a "
            "origem de quase toda CVE desta base, e o upgrade do sistema não as "
            "alcança.[/dim]"
        )
        return False
    console.print(
        f"\n[dim]{base.bundled_manager_note} serão removidos da imagem final "
        "(--keep-manager mantém).[/dim]"
    )
    return True


def _resolve_family(value: str | None) -> OsFamily:
    if value:
        try:
            return OsFamily(value.strip().lower())
        except ValueError as e:
            escolhas = ", ".join(f.value for f in OsFamily)
            raise UnsupportedCombinationError(f"--os inválido: {value!r}. Use: {escolhas}") from e

    console.print("\n[bold]Sistema operacional da base[/bold]")
    for index, family in enumerate(OsFamily, 1):
        nota = (
            "sem shell nem gerenciador de pacotes -- a menor superfície, e nada pode ser instalado"
            if family is OsFamily.DISTROLESS
            else f"libc {family.libc}"
        )
        console.print(f"  {index}. [cyan]{family.value}[/cyan]  [dim]{nota}[/dim]")
    escolha = Prompt.ask(
        "Escolha", choices=[str(i) for i in range(1, len(OsFamily) + 1)], default="1"
    )
    return list(OsFamily)[int(escolha) - 1]


def _resolve_runtime(value: str | None, family: OsFamily) -> Runtime:
    from dockerls.domain.value_objects.base_recipe import RUNTIME_BASES

    disponiveis = [r for r in Runtime if (r, family) in RUNTIME_BASES]
    if value:
        try:
            escolhido = Runtime(value.strip().lower())
        except ValueError as e:
            raise UnsupportedCombinationError(
                f"--runtime inválido: {value!r}. Use: {', '.join(r.value for r in Runtime)}"
            ) from e
        if escolhido not in disponiveis:
            raise UnsupportedCombinationError(
                f"não há imagem base publicada para {escolhido} sobre {family}. "
                f"Disponíveis nesta família: {', '.join(r.value for r in disponiveis)}"
            )
        return escolhido

    console.print(f"\n[bold]Runtime sobre {family.value}[/bold]")
    for index, runtime in enumerate(disponiveis, 1):
        base = RUNTIME_BASES[(runtime, family)]
        console.print(f"  {index}. [cyan]{runtime.value}[/cyan]  [dim]{base.reference}[/dim]")
    escolha = Prompt.ask(
        "Escolha", choices=[str(i) for i in range(1, len(disponiveis) + 1)], default="1"
    )
    return disponiveis[int(escolha) - 1]


def _resolve_packages(value: str | None, family: OsFamily) -> list[str]:
    if not family.installs_packages:
        if value:
            raise UnsupportedCombinationError(
                "distroless não tem gerenciador de pacotes nem shell: não é possível "
                "instalar nada nela"
            )
        console.print(
            "\n[dim]distroless não instala pacotes -- é exatamente o ponto dela. "
            "Nenhum menu a mostrar.[/dim]"
        )
        return []

    if value is not None:
        pedidos = [p.strip() for p in value.split(",") if p.strip()]
        for pedido in pedidos:
            if pedido in REFUSED_PACKAGES:
                raise UnsupportedCombinationError(
                    f"{pedido} não é oferecido: {REFUSED_PACKAGES[pedido]}"
                )
        return pedidos

    console.print("\n[bold]Pacotes na imagem base[/bold]")
    console.print(
        "[dim]Cada um existe em toda aplicação que consumir esta base, e toda CVE "
        "dele vira triagem para quem nem sabe que ele está lá.[/dim]\n"
    )
    disponiveis = [c for c in PACKAGE_CATALOG if c.package_for(family)]
    for index, choice in enumerate(disponiveis, 1):
        marca = " [dim](já presente na maioria das bases)[/dim]" if choice.usually_present else ""
        console.print(f"  {index}. [cyan]{choice.key}[/cyan]{marca}")
        console.print(f"       [dim]serve para: {choice.purpose}[/dim]")
        console.print(f"       [yellow]custa:[/yellow] [dim]{choice.cost}[/dim]")

    resposta = Prompt.ask(
        "\nNúmeros separados por vírgula (vazio = nenhum pacote)", default="", show_default=False
    ).strip()
    if not resposta:
        return []

    escolhidos: list[str] = []
    for parte in resposta.split(","):
        parte = parte.strip()
        if not parte.isdigit() or not (1 <= int(parte) <= len(disponiveis)):
            raise UnsupportedCombinationError(f"escolha inválida: {parte!r}")
        escolhidos.append(disponiveis[int(parte) - 1].key)

    console.print(f"\n[dim]Marcados: {', '.join(escolhidos)}[/dim]")
    # `s`/`n`, não `y`/`n`: a interface inteira está em português, e um prompt
    # que recusa "s" faz a pessoa duvidar do que ela acabou de marcar.
    if Prompt.ask("Confirma?", choices=["s", "n"], default="s", console=console) == "n":
        console.print("[dim]Nada foi escrito.[/dim]")
        raise typer.Exit(EXIT_OK)
    return escolhidos


async def _resolve_digest(recipe: BaseRecipe) -> str:
    """Pergunta ao registry qual digest a tag da base aponta agora."""
    from dockerls.domain.entities.image import DockerImage
    from dockerls.integrations.registry.inspector import RegistryInspector

    base = recipe.base
    inspector = RegistryInspector(guard=build_host_guard())
    try:
        return await inspector.resolve_digest(DockerImage(name=base.image, tag=base.tag))
    except Exception:  # pragma: no cover - rede é o caminho instável
        return ""
    finally:
        await inspector.close()


def _default_title(family: OsFamily, runtime: Runtime) -> str:
    return "base-" + (runtime.value if runtime is not Runtime.NONE else family.value)


def _default_description(family: OsFamily, runtime: Runtime) -> str:
    if runtime is Runtime.NONE:
        return f"Imagem base {family.value}, sem runtime de linguagem"
    return f"Imagem base {family.value} + {runtime.value}"
