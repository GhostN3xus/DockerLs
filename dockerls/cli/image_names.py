"""O nome que aparece na tabela, sem o registry que a coluna ao lado já diz.

A tabela de resultados tem treze colunas e nenhuma largura sobrando. Com
`overflow="fold"`, um nome como `gcr.io/distroless/nodejs22-debian12` era
quebrado no meio da palavra e saía em duas ou três linhas ilegíveis --
enquanto a coluna `Source`, encostada nele, já dizia "Distroless".

Encurtar aqui não é cosmético: o leitor precisa reconhecer *que runtime é
aquele* de relance, e é justamente essa metade que se perdia. `nodejs22-debian12`
diz Node 22 sobre Debian 12; `gcr.io/distrole` / `ss/nodejs22-de` não diz nada.

O corte só acontece quando a coluna vizinha carrega a informação removida.
Um registry que a tabela não identifica -- `ghcr.io/org/app` -- é mostrado
inteiro, porque ali o host *é* a identidade e escondê-lo confundiria duas
imagens diferentes com o mesmo nome final.

A referência completa não se perde em lugar nenhum: `--format json`, a linha
`Pin to:` e a evidência continuam com o nome inteiro, que é o que alguém
copia para um Dockerfile.
"""

from __future__ import annotations

#: Prefixos de catálogos que a coluna `Source` já nomeia.
_REDUNDANT_PREFIXES = (
    "cgr.dev/chainguard/",
    "gcr.io/distroless/",
    "dhi.io/",
    "docker.io/library/",
    "index.docker.io/library/",
)


def display_name(name: str) -> str:
    """O nome do runtime, sem o prefixo que a coluna `Source` repete."""
    value = name.strip()
    for prefix in _REDUNDANT_PREFIXES:
        if value.lower().startswith(prefix):
            return value[len(prefix) :] or value
    return value


def display_reference(name: str, tag: str) -> str:
    short = display_name(name)
    return f"{short}:{tag}" if tag else short
