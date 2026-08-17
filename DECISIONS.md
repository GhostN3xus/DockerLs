# DECISIONS.md

Decisões tomadas durante a implementação autônoma de `dockerls build` e
`dockerls update`. Cada entrada registra a ambiguidade encontrada, as opções
consideradas e por que a escolhida é a mais segura.

---

## D-001 — Mapeamento da árvore de módulos

**Ambiguidade.** A especificação descreve `domain/`, `application/`,
`infrastructure/` e `interface/cli/` na raiz. Este repositório usa
`dockerls/domain/`, `dockerls/application/`, `dockerls/infrastructure/`,
`dockerls/integrations/` e `dockerls/cli/` — a camada de interface chama-se
`cli`, não `interface`, e as integrações de rede vivem em `integrations/`,
não em `infrastructure/`.

**Decisão.** Mapear a especificação sobre a árvore existente:

| Especificação | Neste repositório |
|---|---|
| `domain/build/*` | `dockerls/domain/build/*` |
| `domain/templates/models.py` | `dockerls/domain/templates/models.py` |
| `application/*` | `dockerls/application/use_cases/*` |
| `infrastructure/docker/*` | `dockerls/infrastructure/docker/*` |
| `infrastructure/registry/*` | `dockerls/integrations/registry/*` (já existe) |
| `infrastructure/feeds/eol.py` | `dockerls/integrations/endoflife/` (já existe) |
| `interface/cli/*` | `dockerls/cli/commands/*` |

**Motivo.** Criar uma segunda árvore paralela partiria o projeto em duas
arquiteturas concorrentes. O invariante 6 manda reutilizar o que existe, e a
convenção do repositório vale mais que a nomenclatura do enunciado.

---

## D-002 — `dockerls build` já existe

**Ambiguidade.** A especificação pede "implementar `dockerls build`", mas o
comando **já existe** (`dockerls/cli/commands/build.py`,
`BuildImageUseCase`), com contrato próprio: `--validate-only`,
`--suggest-hardening`, `--hardened`, `--fail-on`, `--ci-mode`,
`--list-templates`, e exit codes 0/1/2 documentados no README.

**Decisão.** **Estender, não substituir.** As opções novas (`--dry-run`,
`--stack`, `--template`, `--platform`, `--fixable-only`, `--apply-vex`,
`--sbom`, `--output`, `--offline`, `--fix`) são acrescentadas ao comando
existente, preservando toda flag atual e o significado dos exit codes.

**Motivo.** Trocar o comando quebraria os pipelines de quem já usa
`--validate-only`/`--ci-mode`, e a especificação não pede quebra de
compatibilidade — pede capacidade nova. Um comando que muda de significado
sem aviso é exatamente a classe de defeito que este projeto vem corrigindo.

**Consequência registrada.** O `--fail-on` do `build` existente aceita
`critical|high|medium|low`; a especificação pede `none|critical|high|medium`.
Aceito a união: `none` passa a ser válido (equivale a não passar a flag) e
`low` continua válido. Nenhum valor antes aceito deixa de ser.

---

## D-003 — `Severity`: reutilizar o enum existente

**Ambiguidade.** A especificação declara `Severity` com valores minúsculos
(`"critical"`). O domínio já tem
`dockerls.domain.entities.vulnerability.Severity`, um `StrEnum` com valores
maiúsculos (`"CRITICAL"`), usado pelos scanners, pelo motor de score, pelos
exporters e pelo SARIF.

**Decisão.** Reutilizar o enum existente, sem introduzir um segundo.

**Motivo.** Invariante 6. Dois enums de severidade no mesmo processo é uma
fonte garantida de comparação silenciosamente falsa (`"critical" != "CRITICAL"`).
Onde a serialização precisar de minúsculas, a conversão é feita na borda.

---

## D-004 — `model_config = ConfigDict(frozen=True)` só nas entidades novas

**Ambiguidade.** O invariante 4 exige entidades de domínio congeladas. As
entidades existentes (`DockerImage`, `ScanResult`, `Vulnerability`) são
mutáveis, e há código que depende disso — `CrossValidator` escreve
`analysis.scan_divergence`, `_verify_tags` escreve `analysis.hub_url`.

**Decisão.** Toda entidade **nova** de domínio nasce `frozen=True`.
As existentes não são retrofitadas neste trabalho.

**Motivo.** Congelar as antigas quebraria caminhos em produção que hoje
funcionam, sem que a especificação peça essa mudança. Fica registrado como
dívida conhecida, não como omissão.

---

## D-005 — AST nova, sem aposentar o parser existente

**Ambiguidade.** Já existe `DockerfileParser` em
`dockerls/infrastructure/dockerfile_validator.py`, baseado em regex por
linha. A especificação exige explicitamente "AST própria (não regex de linha
solta)", com heredoc, `ARG` pré-`FROM`, stages nomeados e `COPY --from`.

**Decisão.** Criar `dockerls/domain/build/dockerfile_ast.py` como parser
novo e puro, e **manter** o parser antigo servindo `analyze-dockerfile`.

**Motivo.** O parser antigo tem 30 testes verdes cobrindo o comportamento de
`analyze-dockerfile`; trocá-lo por baixo seria uma migração não pedida com
risco de regressão. Os dois coexistem até que uma migração explícita seja
solicitada. A duplicação está consciente e registrada aqui.

---

## D-006 — O guard de código morto do projeto governa a ordem de construção

**Ambiguidade.** `tests/unit/test_no_dead_configuration.py` reprova qualquer
símbolo público que nada no pacote alcance. Durante uma construção em
camadas, o módulo de baixo nasce antes do seu consumidor — e fica
temporariamente "morto" pelo critério do guard.

**Decisão.** Não enfraquecer o guard nem adicionar allowlist. Em vez disso:
**nenhum helper é escrito antes do seu consumidor.** Helpers já removidos por
esse critério, para voltar junto com quem os usa:

| Símbolo | Volta no passo |
|---|---|
| `Stage.base_tag` | 4 — resolução de base |
| `BaseCandidate.pinned_reference` | 4 — pin por digest |
| `BaseCandidate.blocking_count` | 7 — motor de política |
| `RuleFinding.location` | 8 — renderização |
| `BuildPlan.manual` | 8 — renderização |
| `compute_cve_delta` | 8 — relatório |

**Motivo.** O guard existe porque este projeto já entregou cinco vezes algo
declarado, documentado e nunca alcançado. Contorná-lo durante a construção é
como a sexta vez começaria. Enquanto o consumidor não existe, o símbolo não
existe.

**Estado atual.** `domain/build/rules.py` e `check_all` ainda não têm
chamador — a wiring do `--dry-run` na CLI é o próximo passo, e é ela que
fecha essa pendência. Enquanto isso, os dois testes do guard estão
**vermelhos de propósito**, e é a primeira coisa a corrigir na próxima
iteração. Nenhum stub silencioso foi criado para escondê-los.

---

## D-007 — A abstração multi-source estende `ImageRepositoryInterface`

**Ambiguidade.** O enunciado pede um `Protocol` novo (`ImageSource`) com
`search`, `resolve`, `get_metadata` e `verify`.

**Decisão.** Não criar um segundo protocolo. `ImageRepositoryInterface` +
`CompositeImageRepository` **já são** a abstração multi-source: interface no
domínio, implementações em `integrations/`, fan-out concorrente com
degradação por fonte. O que faltava não era a interface, era um **registro
nomeado** — que fosse capaz de mapear `--source dhi` para um provedor sem
espalhar `if source == ...`. Foi isso que se acrescentou
(`application/services/source_registry.py`).

**Motivo.** Um segundo protocolo obrigaria todo provedor existente a
implementar as duas faces, ou obrigaria a um adaptador por provedor. Nenhum
dos dois compra capacidade nova: `resolve`/`verify` do enunciado já existem,
como `RegistryInspector` (digest + config) e como `tag_exists`, e ambos
servem a *todas* as fontes em vez de serem reimplementados em cada uma.

---

## D-008 — Scores calculados sobre os fatos determinados, não sobre um denominador fixo

**Ambiguidade.** O enunciado descreve o Hardening Score como uma soma de
pesos fixos (`Non-root +20`, `No shell +15`, ...), o que implica um
denominador constante.

**Decisão.** O denominador é o peso dos fatores **efetivamente
determinados**, e o valor vem acompanhado de `coverage` (quanto do modelo
isso representa) e de `reportable` (falso abaixo de 25%, quando o número
passa a ser exibido como `n/a`).

**Motivo.** Com denominador fixo, uma imagem excelente que ninguém conseguiu
inspecionar pontua trinta e poucos — e esse número é lido como veredito de
hardening, quando na verdade mede a *nossa* falta de acesso. A maior parte
dos fatos do modelo (SUID, shell, gerenciador de pacotes) não é determinável
sem desempacotar o filesystem, coisa que este projeto não faz. Um score que
diz "100 com 31% de cobertura" é verdadeiro e útil; um que diz "34" é falso
e prejudicial. A regra que isso preserva é a mesma do resto do projeto:
**não medido nunca vira medição ruim**, do mesmo jeito que scan falho nunca
vira zero CVE.

**Consequência registrada.** Cobertura passa a ser um insumo de
`Confidence`, e o ranking só consulta hardening quando `reportable` é
verdadeiro — senão um 100 tirado de um fato ganharia de um 85 medido de
verdade.

---

## D-009 — Fatos de imagem são de três estados, e `unknown` não é `false`

**Ambiguidade.** O enunciado pede campos como `has_shell`, `runs_as_non_root`
e `is_distroless`, e diz que o valor deve ser `unknown` quando indeterminado.

**Decisão.** `Tristate` (`TRUE`/`FALSE`/`UNKNOWN`) no domínio, usado em todo
fato de hardening, com uma assimetria explícita na inferência: a presença de
um pacote de shell **prova** shell; a ausência não prova nada e permanece
`UNKNOWN`.

**Motivo.** Um `bool` faz o caminho errado ser o caminho fácil: `not
has_shell` transforma "ninguém olhou" em "não tem shell", e isso vira
crédito num score. A assimetria existe porque uma base derivada de busybox
traz `/bin/sh` sem nomear pacote nenhum — concluir `false` por ausência
seria uma afirmação de hardening que nenhuma evidência sustenta.

**Consequência registrada.** Nome de imagem **nunca** é evidência.
`DockerImage.is_distroless`/`is_alpine`/`is_hardened_source` continuam
existindo e continuam alimentando o bônus qualitativo (mínimo, e limitado
abaixo de um único HIGH) do `SecurityScore` legado, mas não alimentam nem o
Hardening Score nem o Attack Surface Score: lá só entra o que o registry, o
scanner ou uma declaração auditável disseram.

---

## D-010 — DHI é fonte opt-in, e um candidato não escaneável é `UNVERIFIED`

**Ambiguidade.** O enunciado trata DHI como mais um catálogo a fanar por
padrão.

**Decisão.** `dhi` fica **desligado** por padrão (`include_dhi_source =
false`), ligável por execução com `--source dhi`/`--all-sources`.

**Motivo.** `dhi.io` recusa pull anônimo — verificado durante a auditoria: o
endpoint de token responde 401 sem credencial. Numa máquina sem
entitlement, ligar DHI por padrão produziria uma coluna de `UNVERIFIED` em
toda execução, que é *correto* mas ruidoso, e gastaria scans que falham em
cima de candidatos que não podem entrar na tabela. Com credencial
configurada, uma flag liga tudo.

**O que não muda:** metadado de catálogo continua não sendo veredito. Uma
definição DHI que declare `run-as: node` não torna a imagem não-root aos
olhos do DockerLs; se o registry servir o config e ele disser `root`, vale o
config, e a contradição é registrada como achado.

---

## D-011 — Bomba YAML: medir a expansão, não contar aliases

**Ambiguidade.** Nenhuma: o enunciado só exige "parsing seguro" e proíbe
`yaml.load`.

**Decisão.** Além de `SafeLoader` e do teto de bytes, o documento é
**composto** num grafo de nós (onde alias é aresta compartilhada), o tamanho
expandido é calculado sobre esse grafo com memoização e clamp, e só então
`construct_document` roda.

**Motivo.** A primeira implementação contava aliases no texto cru, e o teste
adversarial derrubou essa premissa: a bomba clássica (nove níveis de
aliasing nônuplo) usa ~70 aliases — abaixo de qualquer limite razoável — e
expande para 387 milhões de nós. O guard passava e o parser travava. O que
precisa ser limitado é o **produto**, não a contagem. Fica registrado porque
o erro é sedutor: um limite de aliases *parece* proteger e não protege.

**Consequência registrada.** O teste afirma o tempo de recusa, não só a
exceção. Um guard que recusa depois de expandir executou o ataque em vez de
impedi-lo, e só o tempo distingue os dois casos.
