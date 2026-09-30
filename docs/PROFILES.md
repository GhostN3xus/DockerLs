# Perfis de execução, prazo e saída estruturada

Este documento cobre o que controla **quanto** um `recommend` mede, **quanto tempo** ele pode levar e **em que formato** ele responde. Os números de tempo citados estão em [`PERFORMANCE.md`](PERFORMANCE.md), com a origem de cada um.

## `--profile quick | standard | audit`

Um perfil é um nome para um conjunto de opções que já existiam. Sem `--profile`, **nada muda**: o comportamento é o de antes.

| | `quick` | `standard` | `audit` |
|---|---|---|---|
| Tags medidas (`--budget`) | 8 | 25 (o padrão de sempre) | todas as descobertas |
| Validação cruzada (2º scanner) nas finalistas | não | sim | sim |
| Verificação da tag no registry de origem | sim | sim | sim |
| Inspeção da config OCI das finalistas | sim | sim | sim |
| Threat intel (KEV/EPSS/Exploit-DB/OSV) | só finalistas | todas as medidas | todas as medidas |
| Ordem dos candidatos | representativa (spread) | a de sempre | a de sempre |

`standard` escreve os padrões por extenso: escolhê-lo equivale a não escolher nada numa configuração padrão.

**Os valores de `quick` (8 tags, sem validação cruzada, intel só nas finalistas) são pontos de partida, não resultados de otimização medida.** O que foi medido é o custo relativo de cada perfil num cenário simulado e o custo real de cada etapa numa máquina específica; veja `PERFORMANCE.md`. Se esses valores forem ruins para o seu caso, ajuste com flags: elas vencem o perfil.

### O que um perfil nunca faz

- **Pular é pendente, nunca aprovado.** Toda verificação que o perfil não faz aparece no resultado como *não realizada* (`pending_checks`, e "Not established" na saída). A análise é avaliada como quando você passa `--no-cross-validate` hoje: sem segunda opinião, a confiança é menor — não há passe livre.
- **Intel só nas finalistas é dito.** Os candidatos fora das finalistas ficam com KEV/EPSS/Exploit-DB/OSV `UNKNOWN`, e o resultado registra que a comparação entre eles é limitada por isso. `UNKNOWN` nunca vira "não explorável".
- **Escolha de candidatos por variante.** Com um perfil (ou filtros), os candidatos medidos são escolhidos para cobrir versões *major*, variantes e distribuições diferentes, em vez de as N tags mais novas da mesma família.

### Precedência

```
flag explícita  >  perfil  >  arquivo de configuração / ambiente  >  padrão embutido
```

O perfil é ele mesmo uma escolha explícita na linha de comando, então vence a configuração ambiente; uma flag específica (`--budget 40`, `--no-hub-check`, `--cross-validate`) vence o perfil.

## Filtros de compatibilidade

`--runtime-version` (`22`, `22.5`, `'>=20,<23'`, `20-22`), `--distro` (`alpine`, `debian`, …), `--variant` e `--platform` restringem os candidatos.

Um filtro é **confirmado** quando a fonte publica o dado (por exemplo, as arquiteturas de uma tag) ou depois do scan, pela família de SO que o scanner leu na imagem; é **heurístico** quando só o nome da tag sugere (a versão que a tag "nomeia"). A saída diz qual dos dois valeu. Nada é filtrado por um palpite apresentado como fato.

`alternatives` e `advisor` usam os mesmos filtros. Em uma migração, `direct_replacement` só é verdadeiro quando nada conhecido o contradiz; uma troca de major, de distribuição/libc, de plataforma ou de publicador aparece em `incompatibilities`, cada item marcado `[confirmed]`, `[heuristic]` ou `[unknown]`. O que nenhuma ferramenta daqui consegue atestar (se a sua aplicação sobe, quais bibliotecas nativas ela liga) é listado em `unverified_compatibility`, nunca assumido.

## `--platform os/arch[/variant]`

O padrão continua `linux/amd64`. A referência pedida, a resolvida e a medida são registradas separadamente (`requested`, `resolved`, `measured`). O scan é feito sobre `nome@digest` do **manifesto da plataforma**, e o digest do **índice** multi-arquitetura é guardado à parte. O resultado de uma plataforma nunca é associado a outra; uma plataforma que o índice não publica é `PLATFORM_MISMATCH`, sem fallback para outra arquitetura.

Uma identidade só é **confirmada** com um digest `sha256:<64 hex>` verificado. Sem ela, o scan pode acontecer (a menos que o registry se recuse), mas nada é gravado como evidência imutável, e a saída mostra "Immutable: not confirmed" com o motivo.

## `--time-budget SEGUNDOS`

Um relógio monotônico, iniciado antes de qualquer coisa ser construída, cobre **tudo**: descoberta, preparo de banco, scans, retentativas, enriquecimento e verificações finais.

Quando o prazo acaba, o que já foi medido é **real** e é mostrado, marcado `PARTIAL`, com a lista do que ficou pendente; o subprocesso em andamento é cancelado e encerrado (sem órfãos). Sem `--time-budget`, nenhum código de saída muda.

### Códigos de saída (só com `--time-budget`, ou ao interromper)

| Código | Significado |
|---|---|
| 0 | completo, sem violação |
| 1 | erro operacional (uso, dependência ausente, rede) |
| 2 | veredito: alternativas encontradas / `--fail-on` violado |
| **4** | o prazo acabou antes de qualquer medição terminar: nada foi medido, e isso não diz nada sobre as imagens |
| **5** | resultado **parcial**: o prazo acabou com medições feitas. Um run parcial **nunca** sai com 0 |
| **130** | interrompido (Ctrl-C) |

Uma violação já **provada** pelas medições concluídas mantém o código dela (uma medição parcial não pode *abrandar* uma falha, só deixar de provar uma aprovação). Erro operacional (1) também é mantido.

## Formatos de saída

`--format table` (padrão), `json`, `summary`, `ndjson`.

- **stdout só contém o resultado.** Logs, progresso e diagnósticos vão para stderr; não há ANSI nem texto extra no stdout dos formatos estruturados.
- **`summary`** — um documento JSON versionado (`dockerls.ci-summary/1`) para CI: `status` (`PASS`, `PASS_WITH_PENDING_CHECKS`, `FAIL`, `INCOMPLETE`, `ERROR`), `exit_code`, `completeness`, `blockers`, `pending_checks`, identidade completa da imagem (`requested`/`resolved`/`measured`, plataforma, digest do índice), contagens, proveniência (origem `scan|cache|shared`, versão do scanner, revisão do banco) e idades (medição, banco). Campos desconhecidos são omitidos ou `null`, nunca `0`.
- **`ndjson`** — um evento JSON por linha, progressivo (`dockerls.events/1`): candidatos descobertos, medições, `ranking` **provisório** (`provisional: true`, com `revision`), `ranking_revised` depois do intel, e **exatamente um** evento final (`final: true`). Valores de texto passam pela redação de segredos.

## Cache em camadas (`recommend`, `analyze`, `compare`, `advisor`)

Quatro camadas independentes, cada uma com sua chave e sua validade:

1. **Scan bruto** — chave: digest do manifesto da plataforma + scanner + versão + opções + revisão do banco de vulnerabilidades. Um scan incompleto, com erro ou de identidade não confirmada **não** é reutilizável. Quando a revisão do banco é desconhecida, vale um TTL conservador de 1 h.
2. **Metadados OCI** — fatos da config (`user`, `entrypoint`, …) e o mapeamento `tag → digest` (imutável por digest, TTL de 30 dias).
3. **Threat intel** — por CVE, com fonte e data; cache negativo do OSV (404, 6 h) e do EPSS (1 h, só se a resposta foi plausível).
4. **Avaliação / política** — chaveada pelo scan e pelo *fingerprint* da política: mudar `--max-critical` reavalia sem escanear de novo.

Uma leitura que falha nunca é silenciosa: o *miss* tem motivo (`CORRUPT`, `SCHEMA_MISMATCH`, `IDENTITY_MISMATCH`, `SCANNER_CHANGED`, `OPTIONS_CHANGED`, `DB_REVISION_CHANGED`, `DB_REVISION_UNKNOWN`, `INCOMPLETE_SCAN`, `UNCONFIRMED_IDENTITY`, `EXPIRED`, …). Ele fica em `provenance.cache_note` (JSON) e aparece em `--details`. "Ausente" e "contornado por `--no-cache`" não geram nota. Falha de **escrita** do cache não invalida o scan que acabou de ser feito.

`--no-cache`: nenhuma leitura nem escrita de medições (scans, avaliações, metadados OCI). O threat intel continua usando o próprio cache de feeds. Apenas os arquivos do DockerLs são tocados; arquivos de outras aplicações no mesmo diretório nunca são removidos.

## Runs salvos: `--diff` e `export --run`

Todo `recommend`/`analyze` grava o run (`$XDG_STATE_HOME/dockerls/runs`, por padrão `~/.local/state/dockerls/runs`, arquivos `0600`, diretório `0700`, escrita atômica, retenção dos últimos 50, valores redigidos) e imprime o **run id** (`YYYYMMDDTHHMMSSZ-8hex`).

- `dockerls export --run RUN_ID --format json|csv|html|markdown|sarif` re-renderiza o run **sem escanear, resolver nem consultar nada**. O id é validado por formato e juntado ao diretório do próprio store: não é possível nomear outro caminho.
- `recommend --diff` compara com o run anterior **compatível** (mesmo comando, imagem, plataforma e filtros). Os achados são comparados pela identidade completa `CVE | pacote | versão instalada` — o mesmo CVE num pacote atualizado que segue vulnerável aparece como um achado que saiu e um novo. A causa é atribuída só quando pode ser sabida: `IMAGE_CHANGED` (a tag aponta para outros bytes), `SCANNER_DATABASE_CHANGED`, ambas, `UNEXPLAINED` (mesma imagem e mesma revisão de banco, achados diferentes) ou `NOT_COMPARABLE`. Revisão de banco desconhecida nunca é lida como "banco igual".
