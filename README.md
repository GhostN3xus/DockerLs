# DockerLs

[![CI](https://github.com/GhostN3xus/DockerLs/actions/workflows/ci.yml/badge.svg)](https://github.com/GhostN3xus/DockerLs/actions/workflows/ci.yml)
[![CodeQL](https://github.com/GhostN3xus/DockerLs/actions/workflows/codeql.yml/badge.svg)](https://github.com/GhostN3xus/DockerLs/actions/workflows/codeql.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Typed](https://img.shields.io/badge/mypy-strict-blue)](pyproject.toml)

**Consultor de segurança de imagens Docker dirigido por evidência.** O DockerLs
descobre, normaliza, verifica, escaneia, valida cruzado e ranqueia imagens de
múltiplos ecossistemas confiáveis para identificar a escolha mais segura para
produção -- e explica por quê.

Segurança aqui não é ausência de achados. É uma conclusão sustentada por
evidência verificável: quando a evidência não basta, a ferramenta prefere dizer
**"não foi possível determinar"** a dizer "está seguro".

A pergunta que ele responde não é *"quantas CVEs esta imagem tem?"*, e sim:

> Dado um runtime desejado, qual é a melhor alternativa para produção
> considerando vulnerabilidades, exploração real, EOL, hardening, superfície de
> ataque, manutenção, proveniência, compatibilidade e **confiança dos dados**?

```
DESCOBRIR -> NORMALIZAR -> VERIFICAR -> ESCANEAR -> VALIDAR CRUZADO
   -> HARDENING -> SUPERFÍCIE DE ATAQUE -> CICLO DE VIDA -> PROVENIÊNCIA
   -> RISCO -> RANQUEAR -> RECOMENDAR -> EXPLICAR
```

**Nenhum fornecedor é autoridade.** Docker Hub, Chainguard, Distroless, Docker
Hardened Images, Trivy e Grype são *fontes de dados*. Uma imagem publicada como
"hardened" não é uma imagem segura até que o DockerLs a resolva por digest, a
escaneie e concorde. O veredito é sempre do DockerLs.

---

## Por que o DockerLs?

Um scanner responde *"quantas CVEs esta imagem tem?"*. Essa quase nunca é a
pergunta que você precisa responder. As perguntas reais são *"qual imagem eu
deveria usar?"* e *"o que eu faço com o que foi encontrado?"* — e é sobre elas
que o DockerLs foi construído.

| | Scanner comum | DockerLs |
|---|---|---|
| Escopo | uma imagem que você já escolheu | **todas as tags candidatas**, ranqueadas |
| Fontes | um registry | Docker Hub + Chainguard + Distroless + **Docker Hardened Images**, no mesmo pipeline |
| Identidade | a tag que você digitou | **digest do manifesto**, resolvido antes do scan -- uma tag se move, um digest não |
| Configuração | fora do escopo | **Hardening Score** medido no config OCI da imagem publicada (não root, portas, entrypoint) |
| Superfície | confundida com tamanho | **Attack Surface Score** próprio: shell, gerenciador de pacotes, ferramentas de debug, privilégio |
| Metadados do fornecedor | aceitos como fato | tratados como *declaração*; contradições com o que foi medido viram achado |
| Qualidade da evidência | invisível | **Confidence** (`HIGH`/`MEDIUM`/`LOW`/`UNVERIFIED`) em cada linha |
| Falha de scan | vira "0 vulnerabilidades" | vira `UNVERIFIED`, com causa classificada e sem pontuação |
| Dado ausente | vira `false` | vira `unknown`, e `unknown` nunca credita nem penaliza |
| Veredito de produção | espalhado pelo código | uma política central, com códigos de bloqueio estáveis |
| Reprodutibilidade | nenhuma | versão do DockerLs e do scanner, digest e fingerprint no manifesto |
| Confiança | a palavra de um scanner | **validação cruzada** com um segundo scanner; divergência material é sinalizada, não escondida |
| EOL | fora do escopo | penaliza no score, e uma base EOL nunca é `production ready` |
| Exploração real | só severidade | CISA KEV + EPSS pesam no score |
| Falha técnica | vira "0 vulnerabilidades" | vira **`Unverified`**, com causa classificada e exit code de erro |
| Correção | lista de CVEs | plano de remediação com versões corrigidas **vindas do scanner** |
| Prova | um número | caminho do JSON bruto de cada scan + manifesto por execução |

O princípio que organiza tudo isso: **uma imagem que não pôde ser medida nunca é
apresentada como uma imagem segura.** Um scan que falhou, expirou ou saiu pela
metade manda a tag para a seção `Unverified` — ela não recebe pontuação, não
recebe nível e não entra na recomendação.

---

## Índice

- [Por que o DockerLs?](#por-que-o-dockerls)
- [Instalação](#instalação)
- [Início rápido](#início-rápido)
- [Comandos](#comandos)
- [Exit codes](#exit-codes)
- [Por que falha de scan não é segurança](#por-que-falha-de-scan-não-é-segurança)
- [Segurança de rede](#segurança-de-rede)
- [Fontes de imagens (multi-source)](#fontes-de-imagens-multi-source)
- [Como a recomendação funciona](#como-a-recomendação-funciona)
- [Algoritmo de pontuação](#algoritmo-de-pontuação)
- [Hardening Score](#hardening-score)
- [Attack Surface Score](#attack-surface-score)
- [Confiança (Confidence)](#confiança-confidence)
- [Recomendações por digest](#recomendações-por-digest)
- [Níveis de segurança](#níveis-de-segurança)
- [Modo alternativo](#modo-alternativo)
- [Performance](#performance)
- [Evidências e reprodutibilidade](#evidências-e-reprodutibilidade)
- [Arquitetura](#arquitetura)
- [Configuração](#configuração)
- [Uso com Docker](#uso-com-docker)
- [Desenvolvimento](#desenvolvimento)
- [CI/CD](#cicd)
- [Modelo de segurança](#modelo-de-segurança)
- [Solução de problemas](#solução-de-problemas)
- [Perguntas frequentes](#perguntas-frequentes)
- [Licença](#licença)

---

## Comandos em resumo

| Comando | O que faz | Exit codes |
|---|---|---|
| [`search`](#search) | Lista as tags disponíveis de uma imagem | `0` / `1` |
| [`recommend`](#recommend) | Ranqueia as tags mais seguras e recomenda uma | `0` `1` `2` `3` |
| [`advisor`](#advisor) | Plano de correção completo para a melhor imagem (e migração, se você passar uma tag) | `0` / `1` |
| [`alternatives`](#alternatives) | Alternativas mais seguras para a imagem que você já roda, com trade-offs | `0` `1` `2` |
| [`analyze`](#analyze) | Análise profunda de uma tag: CVEs, CVSS, origem, correção | `0` `1` `2` |
| [`compare`](#compare) | Compara duas ou mais imagens lado a lado | `0` / `1` |
| [`sbom`](#sbom) | Gera SBOM (CycloneDX ou SPDX) via Trivy | `0` / `1` |
| [`export`](#export) | Exporta o relatório em JSON/CSV/HTML/Markdown/SARIF | `0` / `1` |
| [`analyze-dockerfile`](#analyze-dockerfile) | Valida um Dockerfile contra regras de hardening | `0` `1` `2` |
| [`build`](#build) | Valida, constrói, escaneia e (opcionalmente) publica | `0` `1` `2` |
| [`doctor`](#doctor) | Checa as dependências locais (scanners) | `0` / `1` |
| [`health`](#health) | Checa a conectividade com os serviços externos | `0` / `1` |
| [`cache`](#cache) | Inspeciona e limpa o cache de análises | `0` / `1` |
| [`login`](#login) / [`logout`](#logout) | Credenciais do Docker Hub no keyring do sistema | `0` / `1` |
| [`version`](#version) | Versão instalada | `0` |

---

## Instalação

### Pelo PyPI

```bash
pip install dockerls
```

### A partir do código-fonte

```bash
git clone https://github.com/GhostN3xus/DockerLs.git
cd DockerLs
pip install .
```

### Com suporte a keyring (para armazenar credenciais)

```bash
pip install "dockerls[keyring]"
```

### Requisitos

- Python 3.11+
- Trivy (scanner principal) -- instale em https://aquasecurity.github.io/trivy
- Grype (alternativa opcional) -- instale em https://github.com/anchore/grype

---

## Início rápido

```bash
# Encontrar a imagem Node.js mais segura
dockerls recommend node

# Analisar a fundo uma tag específica
dockerls analyze node:22-alpine

# Obter um plano completo de correção
dockerls advisor node

# Comparar duas imagens lado a lado
dockerls compare node:22-alpine node:22-bookworm-slim

# Exportar relatório em JSON
dockerls export node --format json --output report.json
```

---

## Comandos

### search

Busca tags disponíveis no Docker Hub. Não escaneia nada — é a forma barata de ver
o que existe antes de decidir o que medir.

```bash
dockerls search node
dockerls search python --limit 50
```

Saída real (`dockerls search node --limit 5`):

```
                               Tags for node
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Tag                 ┃ Size (MB) ┃ Architecture ┃ Last Updated ┃ Official ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ trixie-slim         │      80.8 │ amd64        │ 2026-08-06   │   Yes    │
│ trixie              │     422.4 │ amd64        │ 2026-08-06   │   Yes    │
│ slim                │      80.8 │ amd64        │ 2026-08-06   │   Yes    │
│ latest              │     422.4 │ amd64        │ 2026-08-06   │   Yes    │
│ current-trixie-slim │      80.8 │ amd64        │ 2026-08-06   │   Yes    │
└─────────────────────┴───────────┴──────────────┴──────────────┴──────────┘

Total: 5 tags
```

**Como ler.** As tags saem ordenadas por `last_updated` (mais recentes primeiro),
que é a ordem em que o Docker Hub as devolve. `Size` e `Architecture` descrevem o
manifesto **amd64** quando ele existe, e o primeiro manifesto disponível caso
contrário. Repare que `trixie-slim`, `slim` e `current-trixie-slim` reportam o
mesmo tamanho: são apelidos do mesmo digest, e é exatamente essa redundância que
o `recommend` colapsa antes de escanear.

**Exit codes:** `0` com tags encontradas, `1` quando não há nenhuma tag ou a
referência é malformada.

### recommend

Recomenda as tags mais seguras com base no scan de vulnerabilidades.

```bash
dockerls recommend node
dockerls recommend node --max-medium 10          # afrouxa o padrão de 5
dockerls recommend nginx --workers 20
dockerls recommend node --format json
dockerls recommend node --fail-on high --no-color
```

`recommend` e `advisor` aceitam `--format json` (saída legível por máquina) e
`--no-color` (texto puro, sem códigos ANSI).

<a id="exit-codes-de-recommend"></a>
`recommend` termina com um código de saída que reflete o resultado, para servir
de portão em CI:

| Código de saída | Significado                                             |
|-----------------|---------------------------------------------------------|
| 0               | Encontrou imagem que atende ao baseline                  |
| 1               | Erro operacional: nenhuma tag encontrada, **nenhuma tag pôde ser escaneada**, configuração inválida, ou `--fail-on` violado |
| 2               | Nenhuma imagem no baseline, mas há alternativas ranqueadas |
| 3               | Tags foram escaneadas e nenhuma delas serve               |

A diferença entre `1` e `3` é deliberada e importa num portão de CI. `3` é um
**veredito**: as candidatas foram medidas e nenhuma passou. `1` é "não sei" —
inclui o caso em que tags foram descobertas mas nenhuma chegou a ser escaneada
(scanner ausente, banco de vulnerabilidades indisponível, rate limit). Um pipeline
que trata os dois como a mesma coisa não consegue distinguir uma infraestrutura
quebrada de um catálogo de imagens ruim.

`advisor` usa apenas `0` (produziu um plano) e `1` (não havia nada sobre o que
aconselhar): ele reporta uma única imagem, então "baseline" e "alternativa" não
são desfechos distinguíveis do ponto de vista dele.

**Quando nada atinge o baseline, o ranking sai mesmo assim**, marcado como
abaixo do alvo. O caminho alternativo filtrava por `critical_count == 0` -- de
novo parte do mesmo critério que o baseline acabara de rejeitar --, então com
toda tag candidata carregando um CRITICAL (o caso comum no Docker Hub) a
execução respondia `No suitable images found` e nada mais, descartando a
informação mais útil que produziu: qual das imagens ruins é a menos ruim. Para
afrouxar o alvo de verdade, use `--max-critical`, `--max-high` e `--max-medium`.

`--fail-on {critical,high,medium}` força o código de saída 1 se o melhor
resultado ainda carregar vulnerabilidades naquela severidade ou acima, mesmo em
modo alternativo -- útil para reprovar um job de CI diante de uma recomendação
alternativa que você não considera aceitável.

#### O que uma recomendação garante

Toda linha da tabela **Recommended Images** passou por três portões. Se uma tag
não passa nos três, ela é reportada à parte e nunca recebe pontuação:

1. **Scan comprovado.** O processo do scanner terminou limpo e o JSON dele foi
   interpretado. Um scan com falha, timeout ou parcial manda a tag para a seção
   `Unverified (technical error)` -- ela não recebe pontuação nem nível.
2. **Pontuação sem contestação.** Os melhores candidatos são reescaneados com o
   segundo scanner (Grype quando o Trivy é o principal, e vice-versa). Se os dois
   divergirem de forma relevante na contagem de CRITICAL/HIGH, a pontuação
   aparece como `!disputed` em vez de um número, com a discrepância logo abaixo.
3. **Tag confirmada no registry de origem.** Tags do Docker Hub são checadas
   contra a API do Hub (`GET /v2/repositories/<ns>/<repo>/tags/<tag>`); tags de
   fontes hardened são checadas contra a listagem do próprio registry. De um
   jeito ou de outro, a coluna `Tag` reflete uma resposta real do registry, nunca
   uma string montada.

A execução abre com duas linhas de resumo. A primeira diz **o que foi
encontrado**; a segunda, **quanto trabalho custou**:

```
OK 12/24 analyzed | X 12 skipped (technical error) | sources: Docker Hub, Chainguard, Distroless
scans: 9 | cache: 3 hit (25%) | deduped: 12 | cross-validated: 5 | workers: 10
log: ~/.local/state/dockerls/logs/dockerls_2026-08-06_13-36-15.log
```

A segunda linha existe porque `12/24 analyzed` não diz se aquilo custou 24 scans
ou 9. Aqui custou 9: doze tags foram colapsadas por apontarem para digests já
vistos, três vieram do cache, e apenas as nove restantes chegaram ao scanner. Os
mesmos números saem em `--format json`, sob a chave `metrics`.

Quando nada atinge o baseline, os critérios exatos são impressos em vez de apenas
o veredito:

```
No image meets the baseline.
Baseline: 0 Critical, 0 High, 5 Medium (and not EOL).
Showing the best candidates found -- all of them below target.
```

E quando **nada pôde ser medido**, a saída diz isso com todas as letras em vez de
fingir um veredito. Saída real, numa máquina sem scanner instalado
(`dockerls recommend node --limit 3 --no-hardened`):

```
OK 0/3 analyzed | X 3 skipped (technical error) | sources: Docker Hub
scans: 2 | deduped: 1 | workers: 10
log: ~/.local/state/dockerls/logs/dockerls_2026-08-16_19-09-16.log

No image could be scanned.
All 3 candidate(s) failed with: SCANNER_MISSING

Suggested action
  Install Trivy or Grype, then re-run. `dockerls doctor` checks for both.

This is a technical failure, not a security verdict: nothing was measured, so
nothing can be said about these images.

! Unverified (technical error)
  These tags were never scored -- no successful scan, no recommendation.
  Causes: SCANNER_MISSING x3
  node:trixie-slim  SCANNER_MISSING: 'trivy' was not found on PATH. Install it ...
  node:trixie       SCANNER_MISSING: 'trivy' was not found on PATH. Install it ...
  node:slim         SCANNER_MISSING: 'trivy' was not found on PATH. Install it ...
  Run with --verbose for the full scanner output.
```

Isso termina em **`1`** (erro operacional), nunca em `3`. O código `3` significa
"procurei e não achei nada utilizável" — uma afirmação sobre as *imagens*, que um
portão de CI tem o direito de tratar como veredito. Aqui nada foi medido, e
reportar isso como veredito seria a única troca que uma ferramenta de segurança
não pode fazer.

Repare também em `deduped: 1`: das três tags, duas apontavam para o mesmo
manifesto, então foram feitos dois scans e não três.

#### Fontes de imagens

O Docker Hub é consultado junto com dois catálogos gratuitos e endurecidos
(hardened), e todas as tags passam pelo mesmo pipeline de scan -- uma imagem
hardened vence por vulnerabilidades medidas, não por reputação. A coluna `Source`
informa de onde veio cada linha.

| Fonte | Registry | Observações |
|-------|----------|-------------|
| Docker Hub | `docker.io` | Listagem completa de tags, com tamanhos e datas |
| Chainguard | `cgr.dev/chainguard/<imagem>` | O nível gratuito acompanha tags móveis (`latest`, `latest-dev`); versões fixadas são recurso pago |
| Distroless | `gcr.io/distroless/<imagem>` | O GCR informa datas de publicação e tamanhos, então essas tags são ordenadas da mais recente para a mais antiga |
| Docker Hardened Images | `dhi.io` | Catálogo público, registry privado: sem credencial os candidatos ficam `UNVERIFIED`. Opt-in via `--source dhi` |

Selecione as fontes com `--source <nome>` (repetível) ou `--all-sources`; veja
[Fontes de imagens](#fontes-de-imagens-multi-source) para a lista completa e o
detalhamento do DHI.

Assinaturas cosign, atestados, SBOMs, apelidos de arquitetura única e duplicatas
fixadas por commit são filtrados das listagens -- não são imagens que alguém
baixaria. Uma fonte inacessível é registrada em log e pulada; ela nunca derruba
uma busca que as outras fontes ainda conseguem responder. Use `--no-hardened`
para consultar apenas o Docker Hub.

#### Saída, logs e evidências

O terminal mostra apenas um indicador de progresso e os resultados. Todos os
diagnósticos -- inclusive o stderr do scanner -- vão para
`$XDG_STATE_HOME/dockerls/logs/dockerls_<timestamp>.log` quando
`XDG_STATE_HOME` estiver definido, ou para
`~/.local/state/dockerls/logs/dockerls_<timestamp>.log` por padrão; use
`--verbose` para espelhá-los também no stderr. Defina `DOCKERLS_LOG_DIR` para
mudar o diretório de log, inclusive se você quiser manter logs no diretório do
projeto.

Nenhum comando emite log de nível `INFO` no stderr em uso normal: o piso do sink
de console é `WARNING`, independente de `DOCKERLS_LOG_LEVEL` (que controla o
nível do **arquivo** de log). `--verbose` reabre o stderr no nível configurado —
`INFO` por padrão, `DEBUG` com `DOCKERLS_LOG_LEVEL=DEBUG`.

O JSON bruto de cada scan é gravado em
`$XDG_STATE_HOME/dockerls/scans/<imagem>_<tag>__<scanner>__<timestamp>.json`
quando `XDG_STATE_HOME` estiver definido, ou em
`~/.local/state/dockerls/scans/<imagem>_<tag>__<scanner>__<timestamp>.json` por
padrão. Isso evita que uma execução casual polua o repositório analisado com
evidências e logs. O bloco `Details` abaixo da tabela aponta cada imagem para
seus próprios arquivos:

```
Details
  1. node:trixie-slim  Docker Hub
     link:     https://hub.docker.com/_/node?tab=tags&name=trixie-slim
     trivy:    ~/.local/state/dockerls/scans/node_trixie-slim__trivy__20260806T153113154282.json
     grype:    ~/.local/state/dockerls/scans/node_trixie-slim__grype__20260806T153119491147.json
  2. node:slim  Docker Hub
     link:     https://hub.docker.com/_/node?tab=tags&name=slim
     trivy:    ~/.local/state/dockerls/scans/node_trixie-slim__trivy__20260806T153113154282.json  (shared digest)
```

`(shared digest)` marca evidências produzidas sob o nome de uma tag irmã: tags
que apontam para o mesmo digest de manifesto são escaneadas uma vez e compartilham
o resultado. Junto é gravado um manifesto por execução ligando cada pontuação
exibida à sua evidência. Defina `DOCKERLS_EVIDENCE_DIR` para mudar o diretório.

O indicador de progresso é renderizado no **stderr** e os resultados no
**stdout**, então `dockerls recommend node > out.txt` mantém o indicador no seu
terminal e grava resultados limpos no arquivo.

| Flag | Efeito |
|------|--------|
| `--verbose` / `-v` | Também imprime logs no stderr |
| `--no-progress` | Desativa o indicador de progresso |
| `--no-cross-validate` | Pula a validação com o segundo scanner (mais rápido) |
| `--no-hub-check` | Pula a verificação de tag no registry (uso offline) |
| `--source <nome>` | Consulta só as fontes indicadas (repetível) |
| `--all-sources` | Consulta todas as fontes, inclusive as opt-in (DHI) |
| `--no-hardened` | Consulta apenas o Docker Hub |

#### Concorrência de scans

O Trivy trava com exclusividade o diretório de cache dele, então scans paralelos
que compartilham um mesmo cache falham com `cache may be in use by another
process: timeout`. O DockerLs baixa o banco de vulnerabilidades uma única vez no
início, depois dá a cada worker concorrente o seu próprio diretório de cache com
o banco vinculado por hard link, e remove esses diretórios ao fim da execução. Se
o hard link não for possível, ele recorre a um único cache compartilhado e
serializa os scans -- mais lento, porém nunca em disputa de trava.
`DOCKERLS_TRIVY_CACHE_DIR` sobrescreve a raiz do cache.

O Grype verifica atualizações do banco de vulnerabilidades a *cada* invocação, o
que é uma ida à rede por imagem. Por isso a validação cruzada roda
`grype db update` uma vez para o lote e depois escaneia com
`GRYPE_DB_AUTO_UPDATE=false`, e as validações em si rodam concorrentemente
(`DOCKERLS_CROSS_VALIDATE_WORKERS`, padrão 5), já que são independentes. A suíte
de aceitação limita o comando inteiro a um orçamento de 30 segundos para cinco
imagens.

### advisor

Consultor de segurança completo, com passos de correção.

```bash
dockerls advisor node
dockerls advisor node --format json

# Passando uma TAG, o advisor também explica a migração a partir dela
dockerls advisor node:22-alpine
```

A saída inclui: melhor imagem atual, pontuação de segurança, detalhamento de
vulnerabilidades, pontuação de correção e um plano de correção passo a passo.

Quando o argumento traz uma tag (`node:22-alpine` em vez de `node`), essa tag é
tratada como a imagem que você roda **hoje**: ela é escaneada pelo mesmo
pipeline e o advisor acrescenta a seção `Migration`, com ganho de pontuação,
trade-offs e checklist. Um nome sem tag mantém o comportamento de sempre.

```
Migration
  CURRENT      node:22-alpine
  RECOMMENDED  node:22-bookworm-slim
  PIN TO       node@sha256:...

  SECURITY IMPROVEMENT  +18.7 points

WHY
  OK CRITICAL: 2 -> 0
  OK HIGH: 5 -> 0
  OK target runs as a non-root account by default
  OK attack surface: 70 -> 25 (lower is better)

TRADE-OFFS
  ! C library changes (musl -> glibc): prebuilt native modules, wheels and cgo
    binaries linked against the old one will not load and must be rebuilt
  ! package manager changes (apk -> apt): every install step in your Dockerfile
    needs rewriting, and package names differ between them

MIGRATION CHECKLIST
  1. rebuild your image against node@sha256:...
  2. rebuild every native dependency for glibc (clear prebuilt binaries first)
  3. run the unit test suite against the rebuilt image
  4. run the integration test suite against the rebuilt image
  5. re-scan the resulting image (`dockerls analyze <your-image>`)
  6. verify runtime behaviour under production-like load
  7. deploy to a canary before rolling out
```

Nada aqui afirma que a migração é compatível — e nada poderia. Nenhum scan
consegue dizer se a sua aplicação continua rodando; é para isso que o checklist
existe.

### alternatives

Alternativas mais seguras para a imagem que você **já roda**, com o custo de
trocar.

```bash
dockerls alternatives node:22
dockerls alternatives node:22 --all-sources
dockerls alternatives python:3.12 --format json
```

A diferença para o `recommend` é a linha de base: aqui existe uma imagem
concreta da qual você depende, e ela é **escaneada pelo mesmo pipeline** dos
candidatos — a comparação é entre duas medições, nunca entre uma medição e uma
reputação.

```
CURRENT
  node:22  Docker Hub
  score 55.0  tier D  C/H/M 2/5/12

RECOMMENDED ALTERNATIVES
┌───┬────────────────────────────┬──────────┬───────┬───────┬────────┬──────┐
│ # │ Image                      │ Source   │ Score │ Delta │ C/H/M  │ Conf │
├───┼────────────────────────────┼──────────┼───────┼───────┼────────┼──────┤
│ 1 │ node:22-bookworm-slim      │ Docker…  │  88.0 │ +33.0 │ 0/0/3  │ HIGH │
│ 2 │ cgr.dev/chainguard/node    │ Chaing…  │  86.5 │ +31.5 │ 0/0/0  │ MEDI │
└───┴────────────────────────────┴──────────┴───────┴───────┴────────┴──────┘
```

Os números acima são **ilustrativos**: nada é fixado no código, tudo sai do scan
da sua execução.

Três recusas deliberadas:

* se a imagem atual **não pôde ser escaneada**, o comando termina em `1` e diz
  isso — sem linha de base, não há melhoria a afirmar;
* candidatos `UNVERIFIED` nunca são oferecidos como alternativa;
* quando nada pontua melhor que o que você já roda, o comando **diz isso**.
  Ficar onde está é um resultado, não uma falha.

| Exit code | Significado |
|---|---|
| `0` | alternativas encontradas (ou a imagem atual já é a melhor) |
| `1` | falha técnica: a imagem atual não pôde ser medida |
| `2` | há alternativas, mas nenhuma atinge o baseline |

### sbom

Gera um inventário de software (SBOM) para uma imagem via Trivy.

```bash
dockerls sbom node:22-alpine --format cyclonedx
dockerls sbom node:22-alpine --format spdx --output node.spdx.json
```

### analyze

Análise profunda de uma tag específica.

```bash
dockerls analyze node:22-alpine
dockerls analyze node:22-alpine --wide

# Saída legível por máquina, para CI
dockerls analyze node:22-alpine --format json
dockerls analyze node:22-alpine --format sarif -o results.sarif

# Portão de CI: reprova se houver achado na severidade indicada ou acima
dockerls analyze node:22-alpine --fail-on critical

# Patch de Dockerfile derivado dos achados
dockerls analyze node:22-alpine --fix
dockerls analyze node:22-alpine --fix --output Dockerfile.hardened
```

**`--fix` emite um patch, não "o seu Dockerfile corrigido".** A ferramenta
analisa uma imagem publicada e nunca viu o seu Dockerfile -- não há como
recuperar um do outro. O que sai é um `FROM <imagem-analisada>` seguido das
camadas que os achados justificam: copie as linhas `RUN` para o seu build, ou
construa a partir daí. Cada camada sai de um dado concreto — o gerenciador de
pacotes vem da distro que o scanner reportou, e os pacotes de linguagem são
**pinados na versão corrigida** que o próprio scanner entregou, em vez de um
`upgrade` cego. Nada é inventado: uma distro que a ferramenta não reconhece não
gera camada nenhuma, e os achados sem correção publicada aparecem listados como
pendência em vez de sumirem. Quando as duas remediações do npm embutido se
aplicam, ambas saem no patch — uma ativa, a outra comentada, porque são
mutuamente exclusivas.

Mostra todas as CVEs encontradas, pontuações CVSS, pacotes afetados e
disponibilidade de correção.

**Ordenação por severidade, não por CVSS.** As linhas saem CRITICAL primeiro,
depois HIGH, e só dentro de cada faixa é que o CVSS decide. Ordenar apenas por
CVSS decrescente empurrava um CRITICAL de nota 7,5 para baixo de sete HIGH de
nota 8,6 -- o achado mais grave ficava escondido na sexta linha.

**A coluna `Src` diz de qual base veio o CVSS.** Severidade e pontuação podem
vir de bases diferentes: o Trivy classifica pela fonte em `SeveritySource` (em
geral o vendor da distro) enquanto o bloco `CVSS` traz números de várias bases.
É por isso que um `CRITICAL` podia aparecer ao lado de um `7.5` e parecer erro
de conta. Agora a pontuação vem da mesma base que definiu a severidade, com
recuo para o NVD quando aquela base não publica nota -- e a base é dita.

**A coluna `Origin` separa pacote de SO de pacote de linguagem.** É a diferença
entre `apk upgrade` (que não resolve nada) e remover o npm da imagem final:
todas as vulnerabilidades de `node:22-alpine` estão em
`/usr/local/lib/node_modules/npm/node_modules/`, isto é, nas dependências do
npm que a imagem embute. Quando esse é o caso, a saída sugere as duas
remediações concretas.

O ID da CVE nunca é truncado: ele é a chave primária do achado, e `CVE-2026…`
não pode ser consultado em lugar nenhum. Num terminal estreito quem cede
largura são as colunas de pacote e versão. Use `--wide` para renderizar a
tabela na largura que ela pedir, sem truncar coluna alguma.

### compare

Comparação lado a lado de duas ou mais imagens.

```bash
dockerls compare node:22-alpine node:22-bookworm-slim
```

### export

Exporta os resultados da análise.

```bash
dockerls export node --format json
dockerls export node --format csv --output report.csv
dockerls export node --format html --output report.html
dockerls export node --format markdown --output report.md
dockerls export node --format sarif --output report.sarif
```

O formato `sarif` produz SARIF 2.1.0, adequado para envio ao code scanning do
GitHub ou a outras ferramentas que entendem SARIF.

### login

Autentica no Docker Hub (aumenta os limites de requisição).

```bash
dockerls login
```

As credenciais são guardadas no keyring do sistema. Alternativamente, defina
variáveis de ambiente:

```bash
export DOCKERHUB_USERNAME=meuusuario
export DOCKERHUB_TOKEN=meutoken
```

### logout

Remove as credenciais armazenadas.

```bash
dockerls logout
```

### doctor

Verifica as dependências locais. É o pré-voo de um job de CI: rode antes de
escanear qualquer coisa.

```bash
dockerls doctor
```

Saída real, numa máquina sem scanner nenhum:

```
DockerLs System Check

  trivy (Primary vulnerability scanner)          Not found
  grype (Fallback scanner / cross-validation)    Not found
  httpx                                          Available
  keyring                                        Available

DockerLs cannot measure anything on this machine.

Cause
  No vulnerability scanner is installed (needs Trivy or Grype).

Suggested action
  Install Trivy:  https://aquasecurity.github.io/trivy
  or install Grype: https://github.com/anchore/grype

Without a scanner, `recommend`, `analyze` and `advisor` report every tag as
unverified rather than as safe.
```

**Como ler.** O requisito é *um* scanner, não o Trivy especificamente — o
`ScannerFactory` funciona só com o Grype. Com apenas um dos dois instalados o
comando passa (`0`) e avisa que a validação cruzada fica indisponível; sem
nenhum, reprova.

**Exit codes:** `0` quando dá para medir, `1` quando não dá. Ele **reprova de
verdade**: um `doctor` que imprime "faltam componentes" e sai `0` deixa o runner
passar no próprio pré-voo e falhar depois, dentro do scan, onde a causa é muito
menos óbvia.

### health

Verifica a conectividade com os serviços externos dos quais a ferramenta depende:
Docker Hub, Chainguard, Distroless, endoflife.date, CISA KEV e EPSS. Termina com
código 1 se algum estiver inacessível ou responder com erro, para servir de
portão em CI.

```bash
dockerls health
```

Saída real:

```
Service Health Check

  Docker Hub API          OK (200)
  Chainguard (cgr.dev)    OK (200)
  Distroless (gcr.io)     OK (200)
  endoflife.date          OK (200)
  CISA KEV                OK (200)
  EPSS (FIRST)            OK (200)

All services reachable.
```

Cada endpoint da lista é um serviço do qual a ferramenta realmente depende **e**
que responde 2xx quando saudável. Um serviço inacessível vira
`Unreachable: ConnectError` e a execução termina em `1`; os demais continuam
sendo checados, então uma indisponibilidade não esconde as outras.

**Exit codes:** `0` com tudo acessível, `1` com qualquer serviço degradado.

### cache

Inspeciona e limpa o cache de análises.

```bash
dockerls cache stats     # o que o cache está guardando
dockerls cache cleanup   # remove só as entradas vencidas
dockerls cache clear     # esvazia tudo
```

Saída real de `dockerls cache stats`:

```
  Location                 /root/.cache/dockerls/cache.db
  Entries                  0
  Expired (reclaimable)    0
  Size on disk             44.0 KB
```

**Como ler.** As entradas vencem preguiçosamente — uma linha velha é descartada
quando alguém tenta lê-la de novo. Uma tag que ninguém consulta mais nunca é
lida, então fica ocupando espaço: `Expired (reclaimable)` é exatamente quanto o
`cleanup` recuperaria agora. `Size on disk` inclui o arquivo `-wal`, que entre
checkpoints pode conter a maior parte dos dados.

O cache é chaveado pelo **digest do manifesto**, não pela tag, e a chave carrega
uma versão de schema. Um rebuild upstream de `node:22-alpine` não é servido pela
entrada antiga, e uma entrada gravada por uma versão anterior do DockerLs nunca é
lida como se fosse atual.

### version

```bash
dockerls version
```

```
DockerLs v1.1.0
```

### analyze-dockerfile

Valida um Dockerfile contra as regras de hardening da OWASP e mostra a tabela de
checks, o score e as sugestões de correção.

```bash
dockerls analyze-dockerfile .
dockerls analyze-dockerfile ./app/Dockerfile --no-suggestions
dockerls analyze-dockerfile . --format json
```

Saída real, contra este Dockerfile deliberadamente ruim:

```dockerfile
FROM node:latest
RUN apt-get update && apt-get install -y curl
ENV API_TOKEN=supersecret123
COPY . /app
CMD ["node", "/app/index.js"]
```

```
╭────────────────────────────╮
│ Dockerfile Analysis Report │
│ Dockerfile.demo            │
╰────────────────────────────╯

Summary: ✅ 2 passed | ⚠️ 6 warnings | ❌ 3 errors

                              Validation Checks
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Status   ┃ Check                ┃ Message                                 ┃ Severity ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ ❌ FAIL  │ base_image_pinned    │ Base image uses 'latest' tag or no tag  │   HIGH   │
│          │                      │ (implies latest)                        │          │
│ ❌ FAIL  │ non_root_user        │ Container runs as root (no USER         │   HIGH   │
│          │                      │ directive or USER root)                 │          │
│ ⚠️ WARN  │ multi_stage_build    │ Single-stage build detected             │  MEDIUM  │
│ ❌ FAIL  │ secrets_not_in_env   │ Potential secrets in ENV: API_TOKEN     │ CRITICAL │
│ ⚠️ WARN  │ package_cache_clean  │ Package manager cache not cleaned       │  MEDIUM  │
│ ⚠️ WARN  │ healthcheck_present  │ No HEALTHCHECK directive                │   LOW    │
│ ⚠️ WARN  │ security_labels      │ Missing security labels:                │   LOW    │
│          │                      │ security.scanner, maintainer            │          │
│ ⚠️ WARN  │ minimal_base         │ Base image may not be minimal (consider │  MEDIUM  │
│          │                      │ Alpine or Distroless)                   │          │
│ ✅ PASS  │ no_sudo              │ No sudo usage detected                  │   INFO   │
│ ➖ SKIP  │ entrypoint_exec_form │ No ENTRYPOINT directive to check         │   INFO   │
│ ✅ PASS  │ shell_usage          │ CMD uses exec form                      │   INFO   │
│ ⚠️ WARN  │ dockerignore_exists  │ .dockerignore not found                 │   LOW    │
└──────────┴──────────────────────┴─────────────────────────────────────────┴──────────┘

╭────────────────────────╮
│ Security Score: 30/100 │
│ Tier: C                │
│ Production Ready: No   │
╰────────────────────────╯

╭────────────────────╮
│ 💡 Recommendations │
╰────────────────────╯

#1. Upgrade base image
   Use a pinned, minimal base image
   Current: node:latest
   Fix: FROM node:22-alpine or FROM chainguard/node:latest-dev
   Reason: Pinned versions ensure reproducibility; minimal bases reduce attack surface

#2. Add non-root user
   Container should not run as root
   Current: No USER directive
   Fix: RUN adduser -D appuser && USER appuser
   Reason: Running as root increases impact of container breakout

#3. Remove secrets from ENV
   Secrets in ENV are visible in image history
   Current: Secrets: API_TOKEN
   Fix: Use BuildKit secrets: RUN --mount=type=secret,id=token
   Reason: ENV values persist in all layers and can be extracted
```

(sete recomendações no total; as quatro restantes foram omitidas aqui)

**Como ler.** `FAIL` reprova, `WARN` não. Cada recomendação traz o estado atual,
a correção concreta e o motivo — a intenção é que a linha possa ser colada no
Dockerfile, não que sirva de lembrete genérico. `SKIP` significa que a diretiva
não existe para ser checada, e não que ela passou.

**Exit codes:** `2` quando algum check falha (`errors > 0`), `1` quando o
Dockerfile não existe ou não pôde ser lido, `0` quando passa. Avisos nunca
reprovam.

### build

Constrói imagens Docker passando pela validação do Dockerfile antes e pelo scan
de vulnerabilidades depois.

```bash
# Só valida, não constrói nada -- é o modo indicado para portão de CI
dockerls build --validate-only .

# Mesma validação, saída JSON em stdout para o pipeline consumir
dockerls build --validate-only --ci-mode .

# Só as sugestões de hardening
dockerls build --suggest-hardening .

# Build de verdade, reprovando se o scan achar CRITICAL
dockerls build -t minha-app:1.0 --fail-on critical .

# Build, scan e push para o registry
dockerls build -t minha-app:1.0 --fail-on high --push .

# Templates hardened disponíveis para --base
dockerls build --list-templates
```

Saída real de `dockerls build demoapp --validate-only` (mesmo Dockerfile da seção
anterior), com o rodapé que fecha a validação:

```
╭──────────────────────────────────────────────────────────────────────────────╮
│ ❌ Validation Failed                                                         │
│                                                                              │
│ Dockerfile validation failed: 3 error(s) -- base_image_pinned: Base image     │
│ uses 'latest' tag or no tag (implies latest); non_root_user: Container runs   │
│ as root (no USER directive or USER root); secrets_not_in_env: Potential       │
│ secrets in ENV: API_TOKEN                                                    │
╰──────────────────────────────────────────────────────────────────────────────╯
```

Exit code: `2`. Nada foi construído.

A mesma execução com `--ci-mode` produz JSON estruturado em stdout, que é o que o
pipeline consome (saída real, truncada):

```json
{
  "status": "FAILED",
  "exit_code": 2,
  "report": {
    "build_id": "0a822d4afbd9c950",
    "timestamp": "2026-08-16T19:12:06.007864+00:00",
    "image": "",
    "dockerfile_path": "demoapp/Dockerfile",
    "security_score": 30,
    "security_tier": "C",
    "validation": {
      "dockerfile_path": "demoapp/Dockerfile",
      "passed": 2,
      "warnings": 6,
      "errors": 3,
      "checks": [
        {
          "check": "base_image_pinned",
          "status": "FAIL",
          "message": "Base image uses 'latest' tag or no tag (implies latest)",
          "severity": "HIGH",
          "line": null
        }
      ]
    }
  }
}
```

Repare que o `exit_code` também vem **dentro** do documento: um consumidor que já
capturou o stdout não precisa correlacionar com o status do processo.

`--validate-only` e `--suggest-hardening` renderizam a mesma tabela de checks que
`analyze-dockerfile`, com o resumo das regras violadas ao final. Em `--ci-mode` a
saída é JSON estruturado em stdout, sem cores e sem tabela, contendo o relatório
completo — inclusive quando a validação reprova, que é exatamente quando o CI
precisa saber qual regra falhou.

Uma validação com `errors > 0` barra o build (`--force` ignora e constrói assim
mesmo).

`--fail-on` aceita `critical`, `high`, `medium` ou `low`, e cada nível reprova
também tudo que for mais severo que ele. Um valor fora dessa lista é rejeitado
antes do build começar — um limiar que a ferramenta não entende viraria um
portão aberto com cara de fechado. Pelo mesmo motivo, `--fail-on` sem nenhum
scanner disponível termina em `1` (o portão não pôde ser avaliado), nunca em `0`.

`--push` publica a tag **depois** dos portões: uma imagem que reprovou no scan
não é publicada.

#### `--hardened` é gerado no build, não na validação

`--hardened`/`--base` escrevem `Dockerfile.hardened` no diretório de contexto.
Combinado com `--validate-only`, **nada é escrito em disco**: um dry-run não tem
efeito colateral. Para gerar o arquivo, rode o build sem `--validate-only`.

### Exit codes

Os comandos que **avaliam um artefato seu** (`build`, `analyze-dockerfile`)
seguem esta tabela. É o contrato do qual um pipeline pode depender:

| Código | Significado | Quando acontece |
| --- | --- | --- |
| `0` | Sucesso | O comando rodou e nada violou política. |
| `1` | Erro de execução | Dependência ausente, falha de rede, Dockerfile inexistente, `--tag` faltando, JSON inválido em `--build-args`/`--labels`, erro do `docker build`. Nada foi medido, então o resultado não diz nada sobre segurança. |
| `2` | Política violada | O comando rodou bem e o resultado reprova: validação com `errors > 0`, ou `--fail-on` acionado. É o código que um portão de CI deve tratar como "essa imagem não passa". |

A distinção entre `1` e `2` importa: `1` significa "não sei", `2` significa "sei,
e reprovou". Um pipeline que trata os dois como falha genérica não consegue
diferenciar uma indisponibilidade do scanner de uma imagem realmente insegura.

`recommend` **não** cabe nessa tabela, e por um motivo: ele não avalia um
artefato seu, ele escolhe entre candidatos. "Não achei nada no baseline, mas
achei alternativas" é um desfecho que `0`/`1`/`2` não sabem expressar, então
`recommend` usa a escala própria de quatro códigos
[documentada acima](#exit-codes-de-recommend). Os demais comandos
(`search`, `compare`, `analyze`, `advisor`, `sbom`, `export`, `login`, `logout`,
`cache`) usam apenas `0` para sucesso e `1` para falha; `health` usa `1` para
"algum serviço degradado".

---

## Por que falha de scan não é segurança

Esta é a seção mais importante do README, e a razão de o projeto existir na
forma em que existe.

Um scanner que não conseguiu rodar produz **zero achados**. Um scanner que
rodou numa imagem impecável produz **zero achados**. Os dois números são
idênticos, e toda ferramenta que os trata igual acaba dizendo, com a mesma
confiança, "nenhuma vulnerabilidade encontrada" nos dois casos — sendo que só
um deles é uma afirmação sobre a imagem.

```
Trivy não instalado           ->  0 achados  ->  "imagem limpa"?     NÃO
Banco de vulnerabilidades off ->  0 achados  ->  "imagem limpa"?     NÃO
Scan expirou aos 300s         ->  0 achados  ->  "imagem limpa"?     NÃO
Registry recusou o pull       ->  0 achados  ->  "imagem limpa"?     NÃO
Scan parcial (alvos ilegíveis)->  0 achados  ->  "imagem limpa"?     NÃO
Scan completo, nada encontrado->  0 achados  ->  "imagem limpa"?     sim
```

No DockerLs, os cinco primeiros produzem `UNVERIFIED`: sem pontuação, sem
nível, sem recomendação, sem "production ready" — e com a causa classificada.
Só o último produz um veredito.

O mesmo princípio se aplica a tudo que a ferramenta não conseguiu determinar:

| Situação | O que **não** se conclui | O que o DockerLs diz |
|---|---|---|
| Catálogo de EOL fora do ar | "a release está em suporte" | `eol_status: unknown`, e isso aparece nos trade-offs |
| CISA KEV inacessível | "não há CVE explorado" | `kev_status: unknown`; a frase afirmativa não é impressa |
| EPSS não retornado | "probabilidade baixa" | `epss_known: false` |
| Config OCI não lida | "não tem shell" | `has_shell: unknown`, e a cobertura de hardening cai |
| Segundo scanner ausente | "o primeiro está certo" | confiança limitada a `MEDIUM`, com a lacuna nomeada |

**O veredito é uma política única.** `ProductionReadiness` é o único lugar que
escreve `production_ready`, e ele bloqueia por: não medido, confiança baixa,
EOL confirmado, achados acima do limite, CRITICAL sem correção, divergência
material entre scanners, ou tier abaixo do piso. Cada bloqueio tem um código
estável (`NOT_MEASURED`, `END_OF_LIFE`, ...) que um pipeline lê sem precisar
interpretar prosa.

```
UNVERIFIED
  Evidence gaps:
    - no completed scan: nothing was measured
  Not production ready
    x the scan did not complete, so nothing about this image was measured
    x the evidence behind this result has a material problem
```

```
HIGH
  Evidence:
    - scanned, pinned to a digest, confirmed in its registry
    - corroborated by a second scanner that agreed
  Production ready
```

Nenhuma dessas saídas pode ser confundida com a outra, e é esse o ponto.

---

## Segurança de rede

Uma referência de imagem é entrada do usuário e carrega um hostname.
`dockerls analyze 169.254.169.254/latest` é uma referência bem formada — e
resolvê-la significa requisitar o endpoint de metadados da nuvem. Num runner
de CI, com um nome vindo de um PR ou de uma variável de ambiente, isso é um
primitivo de SSRF.

O DockerLs decide por **resolução**, não por grafia (`localhost` e um nome
cujo registro A aponta para 127.0.0.1 são a mesma requisição), e exige que
**todos** os endereços de um nome passem — o que fecha também o rebinding.

| Configuração | Padrão | Por quê |
|---|---|---|
| `network_allow_loopback` | `false` | é o caminho para serviços do próprio runner |
| `network_allow_link_local` | `false` | `169.254.0.0/16` é onde vivem as credenciais de instância |
| `network_allow_private_networks` | **`true`** | registry interno é infraestrutura legítima e comum |
| `network_allowed_hosts` | `[]` | allowlist explícita, vence os três acima |

Permitir RFC1918 por padrão é deliberado: bloquear `10.x` fecharia o SSRF e
quebraria todo mundo que roda um registry interno. Quem quer o modo estrito
desliga num ajuste.

---

## Fontes de imagens (multi-source)

O DockerLs procura candidatos em vários catálogos ao mesmo tempo e os coloca
todos no **mesmo pipeline**. Uma imagem de catálogo hardened não ganha por
reputação: ela ganha por vulnerabilidade medida, hardening medido e evidência
verificável -- ou não ganha.

| `--source` | Catálogo | Padrão | Observação |
|---|---|---|---|
| `dockerhub` | Docker Hub | sempre | fonte primária, recebe o `--limit` inteiro |
| `chainguard` | Chainguard free tier (`cgr.dev`) | ligado | o tier gratuito publica só as tags móveis |
| `distroless` | Google Distroless (`gcr.io/distroless`) | ligado | único que data as tags via manifesto GCR |
| `dhi` | Docker Hardened Images (`dhi.io`) | **desligado** | catálogo público, registry **exige credenciais** |
| `all` | todos acima | — | equivalente a `--all-sources` |

```bash
# Só o catálogo DHI
dockerls search node --source dhi

# Todos os catálogos configurados, incluindo os opt-in
dockerls recommend node --all-sources

# Dois catálogos específicos
dockerls recommend node --source dockerhub --source chainguard

# Quais fontes este build conhece
dockerls doctor
```

Adicionar um provedor novo é **um `register()`** na camada de wiring
(`SourceRegistry`): nenhum comando conhece nomes de fornecedor, e nenhum `if
source == ...` cresce um braço novo.

### Docker Hardened Images

O DHI é diferente de todo o resto, e a diferença molda a integração inteira:

* o **catálogo** é público — um repositório GitHub com definições declarativas
  de build (pacotes instalados, conta de execução, datas de EOL);
* o **registry** não é — `dhi.io` recusa pull anônimo.

Ou seja: qualquer um descobre; só quem tem credencial escaneia. Isso não é um
problema a contornar, é exatamente o caso que o resto deste projeto foi feito
para tratar com honestidade:

```
Catálogo DHI (declaração)  ->  Registry (digest)  ->  Scanner  ->  Veredito
        │                            │
        └── metadados                └── sem credencial: 401
            declarados                   -> UNVERIFIED, nunca ranqueado
```

> **DHI metadata != veredito de segurança do DockerLs.**
> Uma definição que declara `run-as: node` é uma *declaração*. Se o config OCI
> da imagem publicada disser `root`, o DockerLs mantém o que mediu e registra a
> contradição como achado — é justamente para isso que a comparação existe.

**Custo.** O catálogo tem ~11 mil arquivos, e clonar ou percorrê-lo por
requisição seria inaceitável. O DockerLs faz **uma** chamada à API do GitHub por
TTL (a árvore recursiva), reduz a um índice compacto, guarda em cache, e depois
busca apenas as definições da imagem consultada — via CDN, que não consome a
cota da API. Medido: 1 requisição a frio sobre 11k blobs (14 ms), **0** a quente.

Sem token, a API do GitHub permite 60 requisições/hora para um cliente anônimo.
`DOCKERLS_GITHUB_TOKEN` (somente leitura, sem escopo) eleva esse teto.

---

## Como a recomendação funciona

O pipeline, na ordem em que roda. Cada etapa existe para reduzir trabalho da
seguinte ou para impedir que um resultado não comprovado chegue à tabela.

```
1. Descobrir       Docker Hub + Chainguard + Distroless + DHI, em paralelo,
   │               conforme --source/--all-sources. Assinaturas cosign,
   │               atestados, SBOMs, apelidos de arquitetura e duplicatas
   │               fixadas por commit são filtrados aqui.
   ▼
2. Fixar digest    Toda tag sem digest é resolvida no registry (um HEAD).
   │               É isso que faz a deduplicação funcionar ENTRE catálogos.
   ▼
3. Deduplicar      Tags que compartilham um digest de manifesto viram uma só
   │               unidade de trabalho -- inclusive vindas de fontes distintas.
   ▼
4. Consultar       Análise em cache, chaveada por digest + regras de ignore
   │  o cache      ativas. Um hit pula direto para a etapa 7.
   ▼
5. Escanear        Só o que sobrou. Trivy como principal, Grype como fallback
   │               por scan. Um scan que falha NÃO vira zero: vira Unverified.
   ▼
6. Enriquecer      EOL (endoflife.date), CISA KEV e EPSS.
   │
   ▼
7. Pontuar         SecurityScore -> SecurityTier -> RemediationScore.
   │
   ▼
8. Verificar       A tag existe mesmo no registry de origem? Isso vem ANTES da
   │  a tag        validação cruzada, para não gastar um scan secundário em quem
   │               vai cair -- e para que um candidato promovido no lugar de um
   │               descartado não entre na tabela sem ter sido checado.
   ▼
9. Validar         Os melhores candidatos são reescaneados com o segundo
   │  cruzado      scanner. Divergência material vira `!disputed`.
   ▼
10. Inspecionar    Só os finalistas: o config OCI de cada um é buscado no
   │               registry (com o blob conferido contra o próprio digest) e
   │               vira Hardening Score + Attack Surface Score. Uma declaração
   │               de catálogo preenche apenas o que a medição não determinou,
   │               e nunca a sobrescreve.
   ▼
11. Confiar        Confidence a partir de: scan concluído, concordância entre
   │               scanners, digest resolvido, tag confirmada, cobertura de
   │               hardening. Falha técnica = UNVERIFIED, e ponto.
   ▼
12. Ranquear       Confiança -> vulnerabilidade medida -> hardening ->
   │               superfície -> remediabilidade. Nessa ordem, sempre.
   ▼
13. Explicar       "Why this image?" e "Trade-offs" acompanham a recomendação.
```

**O portão final.** Antes de qualquer coisa sair do use case, a lista selecionada
é reconferida: nenhuma imagem sem scan concluído e com timestamp pode ser
apresentada como recomendação. Se alguma passasse, isso seria um erro de
programação e a execução falha alto em vez de recomendar algo não medido.

**Por que a imagem venceu.** A tabela responde isso em colunas: `Score` e `Tier`
dizem o veredito, `C/H/M` diz o que foi medido, `Fix` diz quanto disso tem
correção disponível, `Rem` diz o quão remediável é, `Source` diz de que catálogo
veio e `Tag` diz que o registry confirmou a existência dela. O bloco `Details`
abaixo aponta cada linha para o JSON bruto que a sustenta.

**O que ainda não está resolvido** aparece explicitamente: `! Requires review`
lista os níveis que obrigam a uma decisão humana, `! Scanner divergence` lista as
pontuações contestadas, e `! Unverified` lista o que não pôde ser medido.

---

## Algoritmo de pontuação

Cada imagem recebe uma pontuação de segurança de 0 a 100:

```
pontuação = 96 - penalidades + bônus      # limitada a [0, 100]
```

As vulnerabilidades medidas é que determinam a pontuação. Penalidades:

| Condição                                             | Penalidade      |
|------------------------------------------------------|-----------------|
| Vulnerabilidade CRITICAL                              | -20 cada        |
| Vulnerabilidade HIGH                                  | -5 cada         |
| Vulnerabilidade MEDIUM                                | -1 cada         |
| EOL (fim de vida)                                     | -20             |
| Vulnerabilidade com exploit confirmado (CISA KEV)     | -10 por vuln    |
| Vulnerabilidade com EPSS >= 0,5 (alta probabilidade prevista de exploração) | -5 por vuln |
| Idade da imagem                                       | -dias_de_idade/365 (teto de 3) |

Sinais qualitativos funcionam como critério de desempate. Somam **4,0** --
deliberadamente menos que um único achado HIGH, para que nenhuma combinação deles
consiga colocar uma imagem com um HIGH ou CRITICAL a mais acima de uma imagem
mais limpa:

| Condição                                             | Bônus  |
|------------------------------------------------------|--------|
| Imagem oficial                                        | +1     |
| Base mínima (Alpine, Distroless ou imagem de fornecedor hardened -- Chainguard, Wolfi, Bitnami) | +1 |
| Assinada digitalmente                                 | +1     |
| Versão LTS                                            | +0,5   |
| Atualizada nos últimos 30 dias                        | +0,5   |

O bônus de base mínima é aplicado uma única vez, mesmo que a imagem atenda a mais
de um sinal (por exemplo, uma imagem Chainguard baseada em Alpine não recebe +2).

Os bônus *podem* superar um ou dois MEDIUM, e isso é intencional: uma imagem
distroless oficial e assinada com dois medium é uma escolha defensável frente a
uma imagem sem nada de especial e sem nenhum.

A pontuação começa em 96 e não em 100 para que uma imagem limpa e com todos os
bônus chegue exatamente a 100 sem ser truncada. Isso importa: com bônus somando
+19 sobre uma base de 100, qualquer imagem razoavelmente bem qualificada batia no
teto, e uma imagem limpa, uma com 1 HIGH, uma com 2 HIGH e uma com 5 MEDIUM
reportavam todas exatamente `100.0`. Não existe bônus separado de "zero
vulnerabilidades" -- zero achados já significa zero penalidade, e premiar de novo
contava o mesmo fato duas vezes.

A idade só move a pontuação quando a fonte de fato informou uma data de
publicação. Registries que listam apenas nomes de tags (Chainguard e a maioria
dos catálogos OCI) não são penalizados pela idade nem recebem o bônus de
atualidade, para não serem punidos por metadados que o registry não publica.

As consultas a CISA KEV e EPSS são feitas em regime de melhor esforço: se esses
feeds estiverem inacessíveis, o DockerLs pontua sem esse sinal em vez de falhar o
scan. Ambos só são consultados quando o scan tem achados CRITICAL ou HIGH a
verificar.

---

## Níveis de segurança

O nível é derivado da **pontuação**, e a escala cobre toda a faixa 0-100:

| Nível | Pontuação | Leitura                                  | Pronto para produção |
|-------|-----------|------------------------------------------|----------------------|
| A     | 90-100    | pronta para produção                     | Sim*                 |
| B     | 75-89     | pronta para produção                     | Sim*                 |
| C     | 60-74     | condicional: exige revisão humana        | Não                  |
| D     | 40-59     | não pronta para produção                 | Não                  |
| E     | 20-39     | não pronta para produção                 | Não                  |
| F     | 0-19      | não usar                                 | Não                  |

\* Uma imagem em EOL nunca é reportada como pronta para produção, qualquer que
seja o nível.

**Trava por CRITICAL:** uma imagem com CRITICAL **sem correção disponível**
nunca passa de C, por mais alta que a pontuação tenha ficado. É um teto, não um
piso -- uma imagem já em F não sobe para C por causa dele.

Níveis que exigem ação aparecem numa seção `Requires review` na saída do
`recommend`, nomeando cada imagem afetada -- um nível C na tabela não passa
despercebido.

> **Mudança de contrato (não lançado).** A escala anterior era S/A/B/C e vinha
> de contagens de vulnerabilidade, não da pontuação. Ela parava em C, então uma
> imagem com pontuação 0,0, 6 CRITICAL e 170 achados recebia exatamente o mesmo
> nível de uma imagem 36 pontos melhor. O nível **S deixou de existir**; quem
> consome o campo `tier` em JSON/CSV/SARIF precisa ajustar.

---

## Hardening Score

Duas imagens com a mesma contagem de CVEs não são igualmente seguras. Uma pode
rodar como root, com shell, gerenciador de pacotes e compilador dentro; a outra
pode rodar como conta sem privilégio e sem nada disso. Nenhum número de CVE
expressa essa diferença — por isso hardening é uma **dimensão separada**, e não
um termo somado ao score de segurança.

### Os fatores e seus pesos

| Fator | Peso | Ganha crédito quando |
|---|---:|---|
| `non-root` | 25 | a conta padrão de execução não é root |
| `no-shell` | 15 | não há shell na imagem |
| `no-package-manager` | 12 | não há gerenciador de pacotes |
| `minimal-packages` | 12 | poucos pacotes instalados (crédito decai de 50 até 200) |
| `no-setuid` | 10 | não há binários SUID/SGID |
| `no-debug-tools` | 8 | não há compiladores nem utilitários de rede |
| `no-privileged-ports` | 8 | nenhuma porta abaixo de 1024 declarada |
| `explicit-entrypoint` | 5 | há entrypoint fixo, e ele não é um shell |
| `healthcheck` | 5 | a imagem declara um healthcheck |

### A regra que sustenta o número: `unknown` nunca pontua

Um fato de segurança tem **três** estados: verdadeiro, falso e *não
determinado*. Colapsar o terceiro em "falso" é a simplificação mais perigosa
disponível aqui: transformaria "ninguém olhou dentro da imagem" em "esta imagem
não tem shell", que é uma afirmação de hardening que ninguém fez.

Por isso o denominador do score é o peso dos fatores **efetivamente
determinados**, e `coverage` diz quanto do modelo isso representa:

```
Hardening: 100  (coverage 31%)   -> tudo o que deu para checar estava bom,
                                     e deu para checar menos de um terço
Hardening: n/a  (coverage 8%)    -> pouco demais para o número significar algo
```

Abaixo de 25% de cobertura o número não é exibido: aparece `n/a`. Um número
com cara de medição, calculado a partir de dois fatos, é pior que nenhum número.

### De onde vem cada fato

| Origem | O que estabelece | Vale como |
|---|---|---|
| `registry` | config OCI do digest resolvido: usuário, portas, entrypoint, healthcheck, camadas | **medição** |
| `scanner` | pacotes observados dentro da imagem | **medição** |
| `catalog` | definição de build publicada pelo fornecedor (DHI) | *declaração* |

A precedência é absoluta: uma medição nunca é sobrescrita por uma declaração.
Quando as duas discordam, a contradição vira achado em `conflicts` — não é
resolvida em silêncio.

E a assimetria que impede o erro clássico: um pacote de shell declarado **prova**
que há shell; a *ausência* dele não prova nada (uma base derivada de busybox
traz `/bin/sh` sem nunca nomeá-lo como pacote). Presença → `true`; ausência →
`unknown`, nunca `false`.

### Hardening nunca mascara vulnerabilidade

O Hardening Score **não** entra no `SecurityScore` e **não** é somado a ele. No
ranqueamento ele só é consultado depois da posição de vulnerabilidade medida, o
que é a razão estrutural de nunca poder compensá-la:

```
Hardening: 98
Vulnerability Risk: CRITICAL

Veredito final:  NOT PRODUCTION READY
```

Uma imagem perfeitamente configurada e cheia de CVEs exploráveis é uma imagem
perfeitamente configurada e vulnerável.

---

## Attack Surface Score

Distinto de hardening, e distinto de novo de vulnerabilidade. Hardening pergunta
*"isto está configurado defensivamente?"*; superfície de ataque pergunta *"se
houver execução de código aqui dentro, o que já está disponível para usar?"*.

| Item | Peso | Por quê |
|---|---:|---|
| `package-manager` | 25 | permite **instalar** o que faltar |
| `shell` | 20 | permite usar o que já está instalado |
| `debug-tools` | 15 | compiladores e utilitários de rede |
| `setuid` | 15 | caminho direto de escalonamento |
| `root-default` | 15 | multiplica o valor de todos os outros |
| `package-volume` | 10 | código instalado que ninguém auditou |

**A escala é invertida: maior é pior.** É a única métrica deste projeto nessa
direção, e isso é dito em toda renderização — `Surf` na tabela vem rotulado como
*lower is better*.

**Tamanho não é superfície.** Uma imagem de 900 MB feita de um único binário
estaticamente ligado tem superfície menor que uma de 40 MB com busybox, apk e
curl. Bytes não pontuam aqui; *pacotes* pontuam, porque cada pacote é uma
funcionalidade instalada.

Como no hardening, o score é calculado só sobre fatos determinados e reporta
`coverage`.

---

## Confiança (Confidence)

Todo número que esta ferramenta imprime é a saída de uma cadeia: descobrir,
resolver digest, escanear, conferir com um segundo scanner, ler a configuração.
Elos quebram o tempo todo. Sem um sinal de confiança, um score tirado de um
scanner sobre uma tag não resolvida é renderizado igual a um score de dois
scanners concordando sobre um digest fixado — e o leitor não tem como distinguir.

| Nível | Significa |
|---|---|
| `HIGH` | escaneado, fixado por digest, confirmado no registry, corroborado por um segundo scanner que concordou |
| `MEDIUM` | escaneado e consistente, com evidência faltando (só um scanner, sem digest, ou pouca inspeção) |
| `LOW` | escaneado, mas com problema material: scanners divergiram, tag não confirmada, ou referência não fixável |
| `UNVERIFIED` | **não houve scan concluído.** Nada pode ser concluído, em direção nenhuma |

`UNVERIFIED` é um **piso**: nenhum outro sinal tira um candidato dele, e o
ranqueamento nunca o coloca acima de algo que foi medido. Um scanner ausente, um
banco de vulnerabilidades que não baixou, um registry que recusou — todos
produzem `UNVERIFIED`, nunca "0 vulnerabilidades".

---

## Recomendações por digest

Uma tag é um ponteiro móvel: `node:22` de hoje não são os mesmos bytes de
`node:22` da semana que vem. Uma recomendação que nomeia só a tag não pode ser
conferida contra o scan que a produziu.

Por isso toda tag sem digest é resolvida no registry **antes** do scan, e a
recomendação registra:

```
repositório · tag · digest · arquitetura · scanner · timestamp do scan
```

Isso paga por si duas vezes:

* **fixação** — a saída diz `Pin to: node@sha256:...`, que é o que deveria ir no
  seu Dockerfile;
* **deduplicação entre fontes** — tags que compartilham manifesto viram um único
  scan, mesmo vindas de catálogos diferentes. Medido no benchmark: 40 tags / 12
  manifestos = 28 scans evitados ao custo de 40 requisições `HEAD`.

O digest é conferido de verdade: ao ler o config OCI, os bytes recebidos são
hasheados e comparados com o digest que os endereçava. Um registry, proxy ou
cache que devolva conteúdo diferente falha nessa comparação e o config é
descartado.

---

## Ignorando achados conhecidos

Crie um `.dockerls-ignore.yaml` no diretório de onde você executa o `dockerls`
para suprimir CVEs específicas da pontuação e das recomendações:

```yaml
ignores:
  - cve: CVE-2024-0001
    justification: "Não alcançável no nosso uso deste pacote"
    expires: 2026-12-31
```

`expires` é opcional; passada a data, a regra deixa de valer e a CVE volta a
contar. Arquivos de ignore malformados ou ausentes são tratados como "sem regras"
em vez de falhar o scan.

Imagens de nível C nunca são recomendadas para produção.

---

## Modo alternativo

Quando nenhuma imagem atende ao baseline (Critical=0, High=0), o DockerLs não
retorna resultado vazio. Em vez disso, ele:

1. Encontra todas as imagens com Critical = 0
2. Ordena pelo menor número de vulnerabilidades HIGH
3. Avalia a disponibilidade de correções
4. Calcula uma pontuação de correção
5. Apresenta a melhor alternativa com um plano de correção

### Pontuação de correção

| Pontuação | Significado                           |
|-----------|---------------------------------------|
| 100       | Todas as vulns têm correção           |
| 80        | A maioria tem correção                |
| 60        | Cerca de metade tem correção          |
| 40        | Poucas têm correção                   |
| 20        | Nenhuma correção disponível           |

---

## Performance

O custo de uma execução do `recommend` é dominado por duas coisas: chamadas de
rede aos registries e processos de scanner. Praticamente todo o trabalho de
performance aqui é sobre **não fazer** o que já foi feito.

### O que reduz trabalho

**Deduplicação por digest.** Tags são apelidos. `node:slim`, `node:trixie-slim` e
`node:current-trixie-slim` apontam para o mesmo manifesto, e escanear as três é
escanear a mesma imagem três vezes. As candidatas são agrupadas pelo digest do
manifesto e escaneadas uma vez só; as irmãs compartilham o resultado, e a
evidência é marcada com `(shared digest)` para que o caminho do arquivo não pareça
pertencer à imagem errada.

**Cache chaveado por digest.** Uma análise é guardada sob o digest, não sob a
tag, com TTL configurável (`DOCKERLS_CACHE_TTL_SECONDS`, padrão 24h). Um rebuild
upstream muda o digest, então o cache nunca serve um veredito sobre bytes que não
existem mais. A chave também carrega as regras de ignore ativas e o estado do
threat intel: uma isenção que venceu deixa de valer imediatamente, em vez de
ficar viva até o TTL expirar.

**SQLite em WAL.** O cache é lido e escrito por um pool de threads. Com o journal
padrão do SQLite um escritor tranca o banco inteiro, os leitores ficam na fila, e
um leitor que desiste é tratado como *miss* — o que significa escanear a imagem de
novo. O cache parava de funcionar exatamente sob carga, e em silêncio. Em WAL
leitores e escritor convivem, inclusive entre dois processos `dockerls`
compartilhando o mesmo arquivo.

**Reuso de conexões HTTP.** Cada cliente mantém um `httpx.AsyncClient` durante
toda a execução, então conexões e handshakes TLS são reaproveitados
(keep-alive) em vez de refeitos a cada requisição.

**Listagens memoizadas com single-flight.** Uma listagem de tags de um registry
hardened é buscada **uma vez por execução**. Antes, cada candidato verificado
refazia a listagem inteira — incluindo o 401 e a busca de token —, e como a
verificação roda em paralelo, um cache simples ainda deixaria todas passarem
juntas; por isso a primeira chamada é serializada por repositório.

**Isolamento do cache do Trivy.** O Trivy tranca com exclusividade o diretório de
cache dele. O banco de vulnerabilidades é baixado uma vez no início e vinculado
por *hard link* no diretório de cada worker, de modo que scans paralelos não
disputam a mesma trava. Sem hard link, o pool degrada para um cache único e
serializa — mais lento, nunca em disputa.

**Banco do Grype atualizado uma vez.** O Grype checa atualização a cada
invocação, o que é uma ida à rede por imagem. A validação cruzada roda
`grype db update` uma vez para o lote e depois escaneia com
`GRYPE_DB_AUTO_UPDATE=false`.

**Validação cruzada só onde importa.** Apenas os melhores candidatos passam pelo
segundo scanner, e só depois da verificação de tag — não faz sentido gastar um
scan secundário num candidato que vai cair.

### Medições

Os números abaixo foram medidos neste repositório e são reproduzíveis. Nenhum
deles é estimativa.

**Descoberta e verificação de tags** (`python benchmarks/bench_discovery.py`).
Cenário: listar as tags de um repositório hardened e depois verificar os dez
candidatos sobreviventes, contra um registry simulado que se comporta como os
reais (desafio 401, busca de token, dados), com 20 ms de latência por requisição.

| Métrica | Antes | Depois | Melhoria |
| --- | ---: | ---: | ---: |
| Requisições HTTP | 33 | 3 | −91% |
| Tempo de parede | 0,128 s | 0,064 s | −50% |

**Cache sob concorrência.** 200 escritas + 200 leituras simultâneas, que é o
padrão de acesso de `recommend --workers 10`:

| Métrica | Antes (journal padrão) | Depois (WAL) | Melhoria |
| --- | ---: | ---: | ---: |
| Tempo de parede | ~0,72 s | ~0,50 s | −31% |

**O que não foi medido, e por quê.** Os tempos ponta a ponta de `recommend`,
`analyze` e `advisor` contra imagens reais dependem do Trivy e do Grype, que não
puderam ser instalados no ambiente onde estas medições foram feitas (o download
dos binários é bloqueado). O tempo de scan e o de validação cruzada portanto
**não têm número aqui** — preferimos declarar a lacuna a publicar uma estimativa.

### Onde olhar quando estiver lento

A segunda linha do resumo do `recommend` é o começo do diagnóstico:

```
scans: 9 | cache: 3 hit (25%) | deduped: 12 | cross-validated: 5 | workers: 10
```

- `scans` alto com `cache` em zero → o cache não está sendo aproveitado; confira
  `dockerls cache stats` e se `--no-cache` não está ligado.
- `deduped` em zero com muitas tags → a fonte não reportou digests, então cada
  tag foi tratada como uma imagem distinta.
- `cross-validated` alto pesa no tempo total; `--no-cross-validate` desliga, ao
  custo de perder a confirmação por um segundo scanner.

Os mesmos números saem em `--format json`, sob `metrics`.

---

## Evidências e reprodutibilidade

Uma pontuação que não pode ser conferida é uma opinião. Toda execução deixa o
material que permite refazer a conta.

**JSON bruto de cada scan.** A saída completa do scanner é gravada em
`$XDG_STATE_HOME/dockerls/scans/...` ou, por padrão, em
`~/.local/state/dockerls/scans/...`. O bloco `Details` liga cada imagem aos
arquivos que sustentam a nota dela — um por scanner que a mediu. Defina
`DOCKERLS_EVIDENCE_DIR` quando quiser guardar esses artefatos junto do projeto.

**Manifesto por execução.** Cada execução grava um manifesto ligando cada
pontuação exibida à sua evidência, com digest, contagens por severidade, status
do scan, divergência entre scanners e estado da verificação de tag.

**Digest, não tag.** O cache e a deduplicação são chaveados pelo digest do
manifesto. Uma evidência sempre corresponde aos bytes que a produziram.

**Divergência é mostrada, não resolvida.** Quando os dois scanners discordam de
forma material na contagem de CRITICAL/HIGH, a pontuação aparece como
`!disputed` em vez de um número, com a discrepância logo abaixo. Escolher um dos
dois números seria apresentar uma confiança que o dado não sustenta.

**Nada de versão inventada.** As versões corrigidas dos planos de remediação vêm
do campo `FixedVersion` do scanner. Um achado sem correção publicada é listado
como pendência, não convertido num `upgrade` genérico.

**O que não é reprodutível, e é honesto dizer.** Bancos de vulnerabilidades mudam
todo dia: a mesma imagem escaneada com uma semana de diferença pode dar
contagens diferentes sem que nada tenha mudado na imagem. É por isso que a
evidência guarda o timestamp do scan, e não apenas o resultado.

---

## Arquitetura

O DockerLs segue Clean Architecture, com separação clara de camadas:

```
dockerls/
  cli/              # Comandos Typer e formatação de saída
  domain/
    entities/        # DockerImage, Vulnerability, ScanResult, Recommendation,
                     #   HardeningFacts (evidência), DeclaredImageMetadata (declaração)
    value_objects/   # SecurityScore, SecurityTier, RemediationScore,
                     #   HardeningScore, AttackSurfaceScore, Confidence, Tristate
    interfaces/      # Interfaces abstratas (portas)
  application/
    use_cases/       # SearchImages, RecommendImages, AnalyzeImage, CompareImages
    services/        # ScannerFactory, CrossValidator, CompositeImageRepository,
                     #   SourceRegistry (catálogos), HardeningAnalyzer (evidência),
                     #   verdict (ranking + explicação), migration (trade-offs)
    dto/             # AnalysisResult, ComparisonResult
  infrastructure/
    config/          # Settings (Pydantic)
    database/        # Modelos SQLAlchemy
    logging/         # Configuração do Loguru com mascaramento de segredos
    templates/       # Dockerfiles hardened servidos por --hardened/--base
    dockerfile_validator.py  # Regras OWASP e provedor de templates
    evidence.py      # Persistência do JSON bruto dos scans
  integrations/
    dockerhub/       # Cliente da API do Docker Hub
    trivy/           # Integração com o scanner Trivy
    grype/           # Integração com o scanner Grype (alternativa)
    registry/        # Catálogos hardened via OCI (Chainguard, Distroless) e
                     #   RegistryInspector (digest + config OCI verificado)
    dhi/             # Catálogo Docker Hardened Images (índice, definições, provider)
    endoflife/       # Verificador endoflife.date
    threat_intel/    # CISA KEV e EPSS
  cache/             # Implementação de cache em SQLite
  exporters/         # Exportadores JSON, CSV, HTML, Markdown, SARIF
  utils/             # Validação de entrada, autenticação, retry, rate limit,
                     #   circuit breaker e parsing YAML com limites explícitos
```

Os dados fluem para dentro: CLI -> Casos de uso -> Domínio. As integrações
externas implementam interfaces do domínio e são injetadas pelo construtor de
dependências.

**Adicionar uma fonte de imagens** não toca em nenhum comando: implemente
`ImageRepositoryInterface` em `integrations/`, e registre um `SourceSpec` em
`build_source_registry()`. O nome vira automaticamente um valor válido de
`--source`, aparece no `doctor` e entra no `--all-sources`. O domínio não importa
`httpx`, nem SDK de registry, nem scanner.

---

## Configuração

As configurações são resolvidas nesta ordem de prioridade: variáveis de ambiente,
depois `~/.config/dockerls/config.toml` (ou
`$XDG_CONFIG_HOME/dockerls/config.toml`), depois os padrões embutidos.

### Variáveis de ambiente

| Variável                        | Descrição                                  |
|---------------------------------|--------------------------------------------|
| DOCKERHUB_USERNAME              | Usuário do Docker Hub                      |
| DOCKERHUB_TOKEN                 | Token de acesso do Docker Hub              |
| XDG_CACHE_HOME                  | Sobrescreve o diretório de cache           |
| XDG_CONFIG_HOME                 | Sobrescreve o diretório do arquivo de config |
| DOCKERLS_ENABLE_THREAT_INTEL    | `false` desativa as consultas a CISA KEV / EPSS |
| DOCKERLS_DISABLE_THREAT_INTEL   | Idem, forma legada (mantida por compatibilidade) |
| DOCKERLS_GITHUB_TOKEN           | Token só-leitura para elevar o limite de 60 req/h da API do GitHub (catálogo DHI) |
| DOCKERLS_<NOME_DA_CONFIG>       | Sobrescreve qualquer outra configuração abaixo (ex.: `DOCKERLS_MAX_TAGS=200`) |

### Arquivo de configuração

```toml
# ~/.config/dockerls/config.toml
max_tags = 200
workers = 20
log_level = "DEBUG"
```

As chaves correspondem aos nomes das configurações da tabela abaixo (snake_case,
sem prefixo).

Toda flag de limite (`--max-critical`, `--max-high`, `--max-medium`,
`--workers`, `--limit`) recorre ao valor configurado quando omitida, então tanto
`DOCKERLS_MAX_MEDIUM=10` quanto uma entrada no `config.toml` fazem efeito. Uma
flag explícita sempre vence a configuração.

### Limites padrão

| Parâmetro     | Padrão  |
|---------------|---------|
| max-critical  | 0       |
| max-high      | 0       |
| max-medium    | 5       |
| workers       | automático (ver abaixo) |
| limit (tags)  | 100     |
| TTL do cache  | 24h     |

### Uso de recursos

Cada worker segura um **processo de scanner**, não uma corrotina: o Trivy
carrega uma base de centenas de MB, desempacota camadas e casa pacotes,
ocupando um núcleo inteiro enquanto isso. Dez deles num runner de dois núcleos
não terminam dez vezes mais rápido — terminam mais devagar e podem levar o job
a ser morto por falta de memória.

Por isso o padrão é `0`, que significa **"dimensione para esta máquina"**:

```
workers = min(CPUs utilizáveis, memória disponível / 768 MB), limitado a 16
```

"CPUs utilizáveis" é a cota real, não o que o host tem. Isso importa porque
esta ferramenta analisa containers e costuma rodar dentro de um, onde
`os.cpu_count()` reporta os núcleos da máquina inteira enquanto o cgroup
permite meio núcleo. São lidos: cota de cgroup (v2 e v1), máscara de afinidade
e `MemAvailable`.

Um valor explícito continua valendo — `--workers 20` entrega 20, com um aviso
no log dizendo o que a máquina comporta. Quem mede o próprio runner tem o
direito de sobrecarregá-lo de propósito; o que não pode é isso acontecer em
silêncio.

```bash
dockerls recommend node              # dimensiona sozinho
dockerls recommend node --workers 2  # explícito, para runner apertado
dockerls recommend node --workers 0  # explicitamente automático
```

### Rede e política de acesso

| Configuração                      | Padrão | O que faz |
|-----------------------------------|--------|-----------|
| `network_allow_private_networks`  | `true`  | Permite registries em faixas RFC1918 |
| `network_allow_loopback`          | `false` | Permite referências que resolvem para loopback |
| `network_allow_link_local`        | `false` | Permite link-local, incluindo o endpoint de metadados |
| `network_allowed_hosts`           | `[]`    | Hosts liberados independentemente de onde resolvem |

### Motor multi-source

| Configuração              | Padrão | O que faz |
|---------------------------|--------|-----------|
| `include_hardened_sources` | `true`  | Consulta Chainguard e Distroless junto do Docker Hub |
| `include_dhi_source`       | `false` | Consulta o catálogo Docker Hardened Images (opt-in: `dhi.io` exige credencial para escanear) |
| `dhi_catalog_ttl_seconds`  | `21600` | Validade do índice do catálogo DHI (6h = 1 requisição de API por janela) |
| `dhi_definition_limit`     | `12`    | Definições lidas por consulta DHI (cada uma é uma requisição de CDN) |
| `github_token`             | `""`    | Eleva o teto anônimo da API do GitHub |
| `resolve_digests`          | `true`  | Fixa toda tag no digest antes do scan (é o que faz a deduplicação funcionar entre fontes) |
| `inspect_image_config`     | `true`  | Busca o config OCI dos finalistas para medir hardening em vez de confiar em declaração |
| `hardened_tag_limit`       | `10`    | Tags trazidas por fonte não primária |

---

## Uso com Docker

### Build

```bash
docker build -t dockerls:latest .
```

### Execução segura

```bash
docker run --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  dockerls:latest recommend node
```

### Docker Compose

```bash
docker compose run dockerls recommend node
```

A imagem Docker segue as boas práticas de segurança Docker da OWASP: build
multi-estágio, imagens base fixadas por digest (Python e Trivy), Trivy copiado da
imagem oficial em vez de instalado via `curl | sh`, usuário não-root, suporte a
sistema de arquivos somente leitura e todas as capabilities removidas.

---

## Desenvolvimento

```bash
# Instalar dependências de desenvolvimento
make dev

# Rodar o linter
make lint

# Rodar o verificador de tipos
make type-check

# Rodar os testes; falha cedo com uma mensagem clara se os extras dev não estiverem instalados
make test

# Rodar a auditoria completa (lint + tipos + testes + segurança)
make audit

# Formatar o código
make format
```

---

## CI/CD

Workflows do GitHub Actions incluídos:

- **CI**: linting com Ruff, verificação de tipos com Mypy, Pytest em Python
  3.11/3.12/3.13
- **Security**: SAST com Bandit, checagem de dependências com pip-audit, scan de
  contêiner com Trivy
- **CodeQL**: code scanning do GitHub
- **Release**: publicação automatizada no PyPI ao enviar uma tag, com atestado
  nativo de proveniência SLSA do GitHub e artefatos assinados via Sigstore
  anexados ao release
- **Dependabot**: atualizações semanais de dependências

Os workflows disparam em qualquer pull request (sem filtro de branch de destino)
e em pushes fora das branches do Dependabot. Um grupo de concorrência junta as
execuções duplicadas de push e pull request e cancela as superadas.

---

## Modelo de segurança

### Modelo de ameaças

O DockerLs opera como ferramenta consultiva somente leitura. Ele:
- Lê da API do Docker Hub (dados públicos)
- Executa Trivy/Grype como subprocessos locais
- Consulta as APIs endoflife.date, CISA KEV e EPSS
- Faz cache dos resultados localmente em SQLite

Ele não:
- Baixa nem executa imagens Docker
- Modifica qualquer configuração do Docker
- Acessa registries privados sem credenciais explícitas
- Transmite dados do usuário a terceiros

### Que dados saem da sua máquina

| Destino | O que é enviado | Quando |
| --- | --- | --- |
| `hub.docker.com` | Nome do repositório e da tag consultados | `search`, `recommend`, `export`, verificação de tag |
| `hub.docker.com` | Usuário e token, num POST de login | Só em `dockerls login` / com `DOCKERHUB_*` definidos |
| `cgr.dev`, `gcr.io` | Nome do repositório consultado | Descoberta em fontes hardened |
| `endoflife.date` | Nome do produto e versão (`node`, `22`) | Checagem de EOL |
| `cisa.gov` (KEV) | Nada: o feed inteiro é baixado | Enriquecimento de threat intel |
| `api.first.org` (EPSS) | **Os IDs de CVE encontrados na imagem** | Enriquecimento de threat intel |
| Trivy / Grype | A referência da imagem, como argumento | Cada scan |

O único item dessa lista que descreve *a sua* imagem é a consulta ao EPSS, que
envia IDs de CVE de imagens públicas. Desligue com
`DOCKERLS_ENABLE_THREAT_INTEL=false` se mesmo isso não for aceitável.

**Nunca é enviado:** conteúdo de imagem, camadas, SBOMs, seu Dockerfile, o
código do seu projeto, nomes de host internos ou credenciais de registry
(exceto o login explícito no Docker Hub).

### Como os subprocessos são executados

- Sempre com **lista de argumentos**, nunca `shell=True` — não há string de
  comando para escapar em lugar nenhum.
- `argv[0]` é resolvido para **caminho absoluto** antes da execução, então um
  diretório gravável no início do `$PATH` não decide qual binário roda. Sequestrar
  o `$PATH` de um scanner de segurança é sequestrar o veredito de um pipeline.
- Referências de imagem passam por validação que rejeita, entre outras coisas,
  qualquer componente começando com `-`. Sem isso, uma referência vinda de uma
  variável de CI como `--ignore-unfixed` chegaria ao `trivy image` como *flag*, e
  não como alvo — controle sobre como (ou se) o scan roda.
- Todo processo é **morto e coletado** no timeout ou no cancelamento. Um scanner
  que sobrevive ao seu timeout continua segurando a trava exclusiva do cache do
  Trivy e atrapalha a execução seguinte.

### Onde ficam as credenciais

No keyring do sistema (`dockerls login`), ou nas variáveis `DOCKERHUB_USERNAME` /
`DOCKERHUB_TOKEN`. Nunca em arquivo de configuração, nunca no cache, nunca nos
arquivos de evidência. Um backend de keyring indisponível degrada para acesso
anônimo — nunca aborta o comando.

### Como os logs mascaram segredos

O mascaramento roda em **todos** os sinks de log e cobre as formas em que uma
credencial costuma aparecer: pares chave/valor em JSON e em `repr` de dicionário,
pares sem aspas (`token=...`), esquemas de autorização (`Bearer`, `Basic`),
credenciais embutidas em URL (`https://user:senha@host`), `curl -u`, corpos
multipart, e formatos autoidentificáveis mesmo sem chave que os introduza (PAT do
Docker, token do GitHub, JWT, chave AWS, token do Slack). O mascaramento é
deliberadamente agressivo: mascarar demais uma linha inócua custa pouco, vazar um
token para um arquivo de log não.

### Operações somente leitura

Tudo, exceto três coisas explícitas: `dockerls build` (roda `docker build`),
`dockerls build --push` (publica, e só depois dos portões), e a escrita do
`Dockerfile.hardened` com `--hardened`/`--base` (que **não** acontece sob
`--validate-only` — um dry-run não tem efeito colateral). O DockerLs não baixa
nem executa imagens; o Trivy e o Grype cuidam disso internamente para escanear.

### Limitações conhecidas

- **A ferramenta confia nos scanners.** Se o Trivy e o Grype não conhecem uma
  vulnerabilidade, o DockerLs também não. A validação cruzada reduz o ponto cego
  de um scanner só, não o elimina.
- **Não há verificação de assinatura.** `is_signed` vem de metadados, não de uma
  verificação cosign feita aqui.
- **Bancos de vulnerabilidades mudam diariamente.** Duas execuções da mesma
  imagem em dias diferentes podem discordar sem que a imagem tenha mudado.
- **Um digest só é tão confiável quanto o registry.** A deduplicação e o cache
  confiam no digest que o registry reporta.

### Alinhamento com a OWASP

- Validação de entrada em todos os nomes de imagem (prevenção de injeção)
- Sem `shell=True` nas chamadas de subprocesso (prevenção de injeção de comando)
- Mascaramento de credenciais em toda saída de log
- Detecção de path traversal em nomes de imagem
- Armazenamento seguro de credenciais via keyring do sistema
- Scan de dependências em CI (pip-audit, Dependabot)
- Scan SAST (Bandit, CodeQL)
- Scan de contêiner (Trivy)

---

## Solução de problemas

### "No scanner available"

Instale o Trivy:
```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

Ou instale o Grype como alternativa:
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

### "Rate limited by Docker Hub"

Autentique-se para aumentar os limites de requisição:
```bash
dockerls login
```

### Scans lentos

Comece pelos números da execução, não pelos parâmetros. A segunda linha do
resumo diz onde o tempo foi:

```
scans: 9 | cache: 3 hit (25%) | deduped: 12 | cross-validated: 5 | workers: 10
```

- Reduza a quantidade de tags: `--limit 20`
- Pule a validação cruzada: `--no-cross-validate`
- Confira o cache: `dockerls cache stats`
- Aumente os workers: `--workers 20` — mas veja abaixo

**Aumentar `--workers` nem sempre acelera.** Cada worker é um processo de scanner
com o próprio diretório de cache; passado o ponto em que a máquina fica sem I/O
ou CPU, mais workers só adicionam disputa. O limite é 50, e valores altos também
pressionam os limites de requisição do Docker Hub. Se `scans` já está baixo por
causa do cache e da deduplicação, workers não é a variável que importa.

### "Unverified (technical error)" em todas as tags

Isso não é um veredito sobre as imagens — é uma falha da execução, e o exit code
é `1`. Olhe a linha `Causes:` do bloco: ela agrupa as falhas por causa
classificada, então noventa tags falhando dizem *um* problema, não noventa.

| Causa | O que significa | O que fazer |
| --- | --- | --- |
| `SCANNER_MISSING` | Nenhum scanner no PATH | `dockerls doctor` |
| `DB_INIT_FAILED` | Banco de vulnerabilidades não ficou pronto | Libere acesso a `ghcr.io` e repita |
| `TIMEOUT` | Scans estouraram o tempo | Aumente `DOCKERLS_SCANNER_TIMEOUT` ou reduza `--workers` |
| `RATE_LIMITED` | Registry limitou as requisições | `dockerls login`, ou repita mais tarde |
| `AUTH_REQUIRED` | O registry exige credencial | `dockerls login` |
| `NOT_FOUND` | As tags não puderam ser baixadas | Confira o nome da imagem |

### Ruído do keyring antes da saída

Se você via algo assim antes dos resultados:

```
ModuleNotFoundError: No module named '_cffi_backend'
thread '<unnamed>' panicked at pyo3-0.20.2/src/err/mod.rs:788:5
```

era um backend de keyring quebrado — comum em container e em runner de CI. A
falha sempre foi tratada (a execução segue anonimamente), mas o texto vinha do
runtime Rust direto no descritor 2, abaixo do ponto onde o Python pode capturar.
Isso está silenciado desde a versão atual; a causa continua registrada no arquivo
de log.

### Problemas de cache

```bash
dockerls cache stats     # veja o que está guardado antes de apagar
dockerls cache cleanup   # remove só o que já venceu
dockerls cache clear     # esvazia tudo
```

Uma base de cache corrompida ou ilegível é tratada como *miss*, nunca como falha
de scan: no pior caso a imagem é escaneada de novo.

---

## Perguntas frequentes

**P: O DockerLs baixa imagens Docker?**
R: Não. O Trivy/Grype cuidam do download da imagem internamente, para escanear.
O DockerLs só consulta metadados no Docker Hub.

**P: Dá para usar com registries privados?**
R: `analyze` e `compare` aceitam qualquer referência válida, inclusive registries
privados com porta (`registry.internal:5000/team/app:tag`), hosts comuns de
registry privado (GHCR, Harbor, ECR, GAR) e referências por digest
(`node@sha256:...`). O scan continua passando pelo Trivy/Grype, então autentique
no registry do jeito que você normalmente faria para essas ferramentas (por
exemplo, `TRIVY_USERNAME`/`TRIVY_PASSWORD`, ou um `~/.docker/config.json` já
autenticado) -- o DockerLs não gerencia credenciais de registry por conta
própria. `search` e `recommend` continuam consultando a API de listagem de tags
do Docker Hub, então ficam limitados a repositórios do Docker Hub (mais os
catálogos hardened do Chainguard e Distroless).

**P: Quão precisa é a pontuação?**
R: A pontuação combina contagem de vulnerabilidades, idade da imagem e tipo de
base. É uma heurística -- sempre revise a lista detalhada de CVEs para decisões
críticas.

**P: E se o Trivy e o Grype estiverem ambos indisponíveis?**
R: O DockerLs reporta o problema. Rode `dockerls doctor` para checar as
dependências.

---

## Licença

Licença MIT. Veja [LICENSE](LICENSE).
