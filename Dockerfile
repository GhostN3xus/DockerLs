# syntax=docker/dockerfile:1
#
# A imagem publicada **não embute um scanner**.
#
# Ela embutia: o binário do Trivy era copiado para o stage final (127,92 MB), e
# as dependências Go dele -- `golang.org/x/crypto`, `stdlib`, `go-git` --
# respondiam por ~330 das 339 vulnerabilidades que o Docker Scout reportava
# contra esta imagem. Nenhuma delas era do código Python deste projeto: eram do
# scanner que viajava dentro dela, pinado numa versão de setembro de 2024.
#
# **Consequência, declarada aqui porque é uma perda real de capacidade:** dentro
# deste container, `recommend`, `analyze`, `compare`, `advisor`, `alternatives`,
# `sbom` e o passo de scan do `build` não conseguem medir nada -- o
# `ScannerFactory` não encontra `trivy` nem `grype` no PATH e devolve
# `SCANNER_MISSING`. Pela política deste projeto isso vira "não verificado", e
# nunca "limpo": a ausência de medição não é um resultado de segurança. Os
# comandos que não dependem de scanner (`analyze-dockerfile`, `controls`,
# `search`, `version`, `cache`, `login`) funcionam normalmente.
#
# Para escanear, rode o `dockerls` num host que tenha trivy ou grype instalado
# (é o modo de uso normal fora de container), ou monte um scanner no PATH deste
# container. O CI não é afetado: `.github/workflows/security.yml` escaneia com a
# `aquasecurity/trivy-action`, que nunca dependeu do binário embutido.
#
# A base é pinada por digest de manifest-list (OCI index), resolvida em
# 2026-08-18 para `python:3.12-slim-bookworm`, então o pin continua resolvendo
# para a plataforma certa em builds multi-arch (linux/amd64, linux/arm64,
# linux/386, linux/arm, linux/ppc64le).
ARG PYTHON_DIGEST=sha256:a116514e19457bcb7af7efe9c3dd0b9b71e85b317694e7882a1c52aa15a78134

FROM python:3.12-slim-bookworm@${PYTHON_DIGEST} AS builder

WORKDIR /build

COPY pyproject.toml .
COPY dockerls/ dockerls/

RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim-bookworm@${PYTHON_DIGEST}

# Os LABELs estavam no stage `builder`, que não vira imagem nenhuma: a imagem
# publicada saía sem `maintainer` e sem `security.scanner`, que são exatamente
# os rótulos que a regra DF007 deste próprio projeto cobra. Aqui eles chegam ao
# manifesto final. As anotações `org.opencontainers.image.*` são as chaves
# pré-definidas da especificação OCI, que é o que permite a alguém respondendo a
# um incidente saber de onde esta imagem veio sem adivinhar pela tag.
LABEL maintainer="GhostN3xus" \
      security.scanner="dockerls" \
      org.opencontainers.image.title="DockerLs" \
      org.opencontainers.image.description="Enterprise Docker Image Security Advisor" \
      org.opencontainers.image.source="https://github.com/GhostN3xus/DockerLs" \
      org.opencontainers.image.licenses="MIT"

# Atualiza os pacotes do sistema **antes** de qualquer outra coisa. O digest
# pinado congela a base no dia em que foi publicada, e foi assim que
# `libexpat1 2.5.0-1` ficou parado nesta imagem com CVE-2024-45491 e
# CVE-2024-45492 (CRITICAL, ambas corrigidas em 2.5.0-1+deb12u1) -- o que
# derrubava `dockerls build --fail-on critical`.
#
# `upgrade` em vez de fixar `libexpat1=2.5.0-1+deb12u1` na mão de propósito:
# fixar corrige o pacote que o scan de hoje viu e trava a atualização de todos
# os que ele ainda não viu. A lista de índices sai na mesma camada que a criou,
# senão os bytes ficam na imagem mesmo depois do `rm` (a regra DF005).
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1001 dockerls && \
    useradd --uid 1001 --gid dockerls --shell /bin/false --create-home dockerls

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
