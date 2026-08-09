# DockerLs

Consultor de segurança de imagens Docker para uso corporativo. Descobre as imagens
Docker mais seguras disponíveis no Docker Hub escaneando vulnerabilidades,
verificando status de fim de vida (EOL) e produzindo planos de correção acionáveis.

O DockerLs não é apenas um scanner -- é um consultor de segurança que recomenda a
melhor imagem para produção e diz exatamente como corrigir o que encontra.

---

## Índice

- [Instalação](#instalação)
- [Início rápido](#início-rápido)
- [Comandos](#comandos)
- [Exit codes](#exit-codes)
- [Algoritmo de pontuação](#algoritmo-de-pontuação)
- [Níveis de segurança](#níveis-de-segurança)
- [Modo alternativo](#modo-alternativo)
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

Busca tags disponíveis no Docker Hub.

```bash
dockerls search node
dockerls search python --limit 50
```

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
| 1               | Erro grave, ou limite de `--fail-on` foi violado         |
| 2               | Nenhuma imagem no baseline, mas há alternativas          |
| 3               | Nada utilizável foi encontrado                           |

`advisor` usa apenas `0` (produziu um plano) e `1` (não havia nada sobre o que
aconselhar): ele reporta uma única imagem, então "baseline" e "alternativa" não
são desfechos distinguíveis do ponto de vista dele.

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

A execução abre com um resumo de uma linha: quantas tags foram analisadas versus
puladas, quais catálogos foram consultados, e o caminho do arquivo de log:

```
OK 12/24 analyzed | X 12 skipped (technical error) | sources: Docker Hub, Chainguard, Distroless
log: logs/dockerls_2026-08-06_13-36-15.log
```

Quando nada atinge o baseline, os critérios exatos são impressos em vez de apenas
o veredito:

```
No image found matching baseline.
Baseline: 0 Critical, 0 High, 5 Medium (and not EOL).
No image met it -- showing the closest alternatives.
```

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

Assinaturas cosign, atestados, SBOMs, apelidos de arquitetura única e duplicatas
fixadas por commit são filtrados das listagens -- não são imagens que alguém
baixaria. Uma fonte inacessível é registrada em log e pulada; ela nunca derruba
uma busca que as outras fontes ainda conseguem responder. Use `--no-hardened`
para consultar apenas o Docker Hub.

#### Saída, logs e evidências

O terminal mostra apenas um indicador de progresso e os resultados. Todos os
diagnósticos -- inclusive o stderr do scanner -- vão para
`logs/dockerls_<timestamp>.log`; use `--verbose` para espelhá-los também no
stderr. Defina `DOCKERLS_LOG_DIR` para mudar o diretório de log.

Nenhum comando emite log de nível `INFO` no stderr em uso normal: o piso do sink
de console é `WARNING`, independente de `DOCKERLS_LOG_LEVEL` (que controla o
nível do **arquivo** de log). `--verbose` reabre o stderr no nível configurado —
`INFO` por padrão, `DEBUG` com `DOCKERLS_LOG_LEVEL=DEBUG`.

O JSON bruto de cada scan é gravado em
`.dockerls/scans/<imagem>_<tag>__<scanner>__<timestamp>.json`, e o bloco
`Details` abaixo da tabela aponta cada imagem para seus próprios arquivos:

```
Details
  1. node:trixie-slim  Docker Hub
     link:     https://hub.docker.com/_/node?tab=tags&name=trixie-slim
     trivy:    .dockerls/scans/node_trixie-slim__trivy__20260806T153113154282.json
     grype:    .dockerls/scans/node_trixie-slim__grype__20260806T153119491147.json
  2. node:slim  Docker Hub
     link:     https://hub.docker.com/_/node?tab=tags&name=slim
     trivy:    .dockerls/scans/node_trixie-slim__trivy__20260806T153113154282.json  (shared digest)
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
```

A saída inclui: melhor imagem atual, pontuação de segurança, detalhamento de
vulnerabilidades, pontuação de correção e um plano de correção passo a passo.

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
```

Mostra todas as CVEs encontradas, pontuações CVSS, pacotes afetados e
disponibilidade de correção.

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

Verifica as dependências do sistema.

```bash
dockerls doctor
```

### health

Verifica a conectividade com os serviços externos dos quais a ferramenta depende:
Docker Hub, Chainguard, Distroless, endoflife.date, CISA KEV e EPSS. Termina com
código 1 se algum estiver inacessível ou responder com erro, para servir de
portão em CI.

```bash
dockerls health
```

### cache

Gerencia o cache de scans.

```bash
dockerls cache clear
dockerls cache cleanup
```

### version

```bash
dockerls version
```

### analyze-dockerfile

Valida um Dockerfile contra as regras de hardening da OWASP e mostra a tabela de
checks, o score e as sugestões de correção.

```bash
dockerls analyze-dockerfile .
dockerls analyze-dockerfile ./app/Dockerfile --no-suggestions
dockerls analyze-dockerfile . --format json
```

Termina com código `2` se algum check falhar (`errors > 0`). Avisos não reprovam.

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

| Nível | Critério                                     | Pronto para produção |
|-------|----------------------------------------------|----------------------|
| S     | Critical = 0, High = 0                       | Sim*                 |
| A     | Critical = 0, High <= 3, todas corrigíveis   | Sim*                 |
| B     | Critical = 0, High <= 10                     | Condicional*         |
| C     | Qualquer Critical, ou muitos High            | Não                  |

\* Uma imagem em EOL nunca é reportada como pronta para produção, qualquer que
seja o nível.

Níveis que exigem ação aparecem numa seção `Requires review` na saída do
`recommend`, nomeando cada imagem afetada -- um nível B na tabela não passa
despercebido.

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

## Arquitetura

O DockerLs segue Clean Architecture, com separação clara de camadas:

```
dockerls/
  cli/              # Comandos Typer e formatação de saída
  domain/
    entities/        # DockerImage, Vulnerability, ScanResult, Recommendation
    value_objects/   # SecurityScore, SecurityTier, RemediationScore
    interfaces/      # Interfaces abstratas (portas)
  application/
    use_cases/       # SearchImages, RecommendImages, AnalyzeImage, CompareImages
    services/        # ScannerFactory, CrossValidator, CompositeImageRepository
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
    registry/        # Catálogos hardened via OCI (Chainguard, Distroless)
    endoflife/       # Verificador endoflife.date
    threat_intel/    # CISA KEV e EPSS
  cache/             # Implementação de cache em SQLite
  exporters/         # Exportadores JSON, CSV, HTML, Markdown, SARIF
  utils/             # Validação de entrada, auxiliares de autenticação e retry
```

Os dados fluem para dentro: CLI -> Casos de uso -> Domínio. As integrações
externas implementam interfaces do domínio e são injetadas pelo construtor de
dependências.

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
| DOCKERLS_DISABLE_THREAT_INTEL   | Desativa as consultas a CISA KEV / EPSS    |
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
| workers       | 10      |
| limit (tags)  | 100     |
| TTL do cache  | 24h     |

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

# Rodar os testes
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

### Alinhamento com a OWASP

- Validação de entrada em todos os nomes de imagem (prevenção de injeção)
- Sem `shell=True` nas chamadas de subprocesso (prevenção de injeção de comando)
- Mascaramento de credenciais em toda saída de log, cobrindo JSON, TOML,
  querystrings, corpos multipart, credenciais embutidas em URL, `curl -u` e
  formatos de credencial autoidentificáveis (PAT do Docker, token do GitHub,
  JWT, chave AWS, token do Slack)
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

- Reduza a quantidade de tags: `--limit 20`
- Aumente os workers: `--workers 20`
- Os resultados ficam em cache por 24 horas
- Pule a validação cruzada com `--no-cross-validate`

### Problemas de cache

```bash
dockerls cache clear
```

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
