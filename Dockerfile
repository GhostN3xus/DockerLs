# syntax=docker/dockerfile:1
#
# Base Alpine, e o motivo é medido, não estético.
#
# Sobre a base Debian slim, o `trivy` reportava seis CRITICAL e **nenhuma
# delas tinha versão de correção publicada** -- `apt-get upgrade` não resolvia
# uma sequer:
#
#   libsqlite3-0  CVE-2025-7458                                    (corrigida só no trixie)
#   zlib1g        CVE-2023-45853                                   (corrigida só no trixie)
#   perl-base     CVE-2026-13221, CVE-2026-42496,
#                 CVE-2026-57433, CVE-2026-8376                    (vulnerável em toda release estável)
#
# As quatro do `perl` são o caso interessante: o DockerLs não invoca perl em
# lugar nenhum. Ele está na imagem porque `perl-base` é `Essential: yes` no
# Debian, então nem `apt-get purge` o remove sem quebrar o `dpkg`. Segundo o
# rastreador de segurança do Debian, elas seguem vulneráveis também no trixie
# -- só têm correção no `sid`, que não é base de produção. Numa distribuição
# sem dpkg, esse pacote simplesmente não existe, e com ele somem quatro das
# seis. As outras duas somem porque o Alpine carrega `zlib` e `sqlite-libs`
# mais novos que os do bookworm.
#
# O custo é real e está declarado: a libc passa a ser musl, não glibc. Isso é
# aceitável aqui porque toda dependência compilada deste projeto
# (`pydantic-core`, `sqlalchemy`, `pyyaml`, `greenlet`, `rpds-py`) publica
# wheel `musllinux` -- verificado no PyPI --, então nada é compilado no build e
# nenhuma toolchain entra na imagem.
#
# A imagem **não embute um scanner**. O binário do Trivy era copiado para o
# stage final (127,92 MB) e as dependências Go dele respondiam por ~330 das 339
# vulnerabilidades que o Docker Scout reportava contra esta imagem -- nenhuma
# do código Python deste projeto.
#
# **Consequência, declarada porque é perda real de capacidade:** dentro deste
# container, `recommend`, `analyze`, `compare`, `advisor`, `alternatives`,
# `sbom` e o passo de scan do `build` não medem nada -- o `ScannerFactory` não
# encontra `trivy` nem `grype` no PATH e devolve `SCANNER_MISSING`. Pela
# política deste projeto isso vira "não verificado", e nunca "limpo": a
# ausência de medição não é um resultado de segurança. Os comandos que não
# dependem de scanner (`analyze-dockerfile`, `controls`, `search`, `version`,
# `cache`, `login`) funcionam normalmente. Para escanear, rode o `dockerls` num
# host com trivy ou grype instalado. O CI não é afetado: ele escaneia com a
# `aquasecurity/trivy-action`, que nunca dependeu do binário embutido.
#
# A base é pinada por digest de manifest-list (OCI index), resolvida em
# 2026-08-18 para `python:3.12-alpine`, então o pin continua resolvendo para a
# plataforma certa em builds multi-arch.
ARG PYTHON_DIGEST=sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31

FROM python:3.12-alpine@${PYTHON_DIGEST} AS builder

WORKDIR /build

COPY pyproject.toml .
COPY dockerls/ dockerls/

RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-alpine@${PYTHON_DIGEST}

# Os LABELs estavam no stage `builder`, que não vira imagem nenhuma: a imagem
# publicada saía sem `maintainer` e sem `security.scanner`, que são exatamente
# os rótulos que a regra DF007 deste próprio projeto cobra. As anotações
# `org.opencontainers.image.*` são as chaves pré-definidas da especificação
# OCI, que é o que permite a alguém respondendo a um incidente saber de onde a
# imagem veio sem adivinhar pela tag.
LABEL maintainer="GhostN3xus" \
      security.scanner="dockerls" \
      org.opencontainers.image.title="DockerLs" \
      org.opencontainers.image.description="Enterprise Docker Image Security Advisor" \
      org.opencontainers.image.source="https://github.com/GhostN3xus/DockerLs" \
      org.opencontainers.image.licenses="MIT"

# O digest pinado congela a base no dia em que foi publicada; sem isto, um
# pacote corrigido depois dessa data continuaria velho na imagem. `--no-cache`
# não deixa índice para trás, então não há o que limpar numa camada seguinte
# (a regra DF005).
RUN apk upgrade --no-cache

RUN addgroup -g 1001 dockerls && \
    adduser -u 1001 -G dockerls -h /home/dockerls -s /sbin/nologin -D dockerls

COPY --from=builder /install /usr/local

RUN mkdir -p /home/dockerls/.cache/dockerls && \
    chown -R dockerls:dockerls /home/dockerls

USER dockerls
WORKDIR /home/dockerls

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["dockerls", "version"]

ENTRYPOINT ["dockerls"]
CMD ["--help"]
