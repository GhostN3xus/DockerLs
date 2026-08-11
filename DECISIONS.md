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
