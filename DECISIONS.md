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

---

## D-012 — `ProductionReadiness` é uma política central, não uma propriedade do tier

**Ambiguidade.** `production_ready` já existia como propriedade de
`SecurityTier`, e a regra parecia completa: tier A/B e não-EOL.

**Decisão.** Criar `domain/value_objects/production_readiness.py` como
**única** fonte do veredito, consumindo tier, confidence, verificação do
scan, EOL tri-state, contagens e divergência material. `ImageAnalysis.
production_ready` passa a ser escrito só por ela, e o default do campo virou
`False`.

**Motivo.** O tier enxerga o score e nada mais. Ele não sabe se o scan
terminou — então um scan `PARTIAL` sem achados nos alvos que conseguiu ler
produzia score alto, tier A e `production_ready = True`, na mesma análise que
reportava `confidence = UNVERIFIED`. Uma análise que afirma as duas coisas é
pior que uma que não afirma nenhuma, e o campo contraditório é justamente o
que um portão de CI lê.

**Consequência registrada.** O default `False` é deliberado: uma análise que
nunca passou pela política não é "pronta por omissão". `SecurityTier.
production_ready` continua existindo como a regra de nível de tier que a
política consome, com um docstring dizendo, com todas as letras, que não é o
veredito.

---

## D-013 — Confiança mínima para produção é MEDIUM, não HIGH

**Ambiguidade.** Se `HIGH` exige validação cruzada, exigir `HIGH` para
produção parece a leitura mais segura.

**Decisão.** O piso é `MEDIUM`.

**Motivo.** `HIGH` requer um segundo scanner. Exigir isso transformaria o
veredito numa afirmação sobre o *toolchain do operador* em vez de sobre a
imagem: numa máquina com só o Trivy instalado, nenhuma imagem do mundo seria
production ready, e o campo perderia sentido. `MEDIUM` já exige scan
concluído, sem divergência material e com referência fixada ou confirmada —
que é evidência suficiente para uma decisão, com as lacunas nomeadas ao lado.

---

## D-014 — Ausência de dado nunca vira dado favorável (EOL, KEV, EPSS)

**Ambiguidade.** As três integrações externas degradavam "para não quebrar o
scan" — `is_eol` devolvia `False`, o KEV devolvia conjunto vazio, o EPSS
devolvia dicionário vazio.

**Decisão.** Cada uma passa a distinguir *consultado* de *não consultado*:
`eol_status` tri-state, `kev_status` tri-state, `epss_known`.

**Motivo.** Degradar para "sem sinal" é correto para o *fluxo*; o erro estava
em traduzir "sem sinal" como "sem risco". O caso mais grave era o KEV: com o
catálogo fora do ar, todo CVE ficava `exploit_known=False` e o relatório
imprimia, afirmativamente, `no known-exploited (CISA KEV) vulnerabilities` —
a frase mais forte que a ferramenta produz sobre exploração real, emitida
exatamente quando nada foi consultado.

**Consequência registrada.** A frase afirmativa agora nomeia quantos achados
foram de fato checados. `UNKNOWN` não penaliza o score (não há evidência de
risco) e também não credita (não há evidência de segurança): aparece nos
trade-offs e limita a confiança.

---

## D-015 — Política de rede: bloquear loopback e link-local, permitir RFC1918

**Ambiguidade.** Uma referência de imagem carrega um hostname e é entrada do
usuário. Bloquear tudo que é privado fecha o SSRF; também quebra todo
registry interno, que é infraestrutura legítima e comum.

**Decisão.** Padrão: **loopback e link-local bloqueados**, **RFC1918
permitido**. Ambos configuráveis, com allowlist de hosts vencendo os dois.
A decisão é tomada por **resolução**, não por grafia, e *todos* os endereços
que um nome resolve precisam passar.

**Motivo.** `169.254.0.0/16` é onde os provedores servem credencial de
instância — não existe registry legítimo ali, e é o alvo real. Loopback é o
caminho para serviços do próprio runner. Já `10.x`/`192.168.x` é onde os
registries internos de verdade moram, e uma ferramenta que não consegue olhar
para `registry.internal:5000` não é usável. Julgar por resolução fecha o
caso em que um nome inócuo aponta para 127.0.0.1 — e exigir que *todos* os
endereços passem fecha o rebinding, em que uma resposta pública e uma
loopback chegam juntas.

**Consequência registrada.** A regra vive no domínio e a resolução DNS na
infraestrutura, porque o guarda de arquitetura proíbe `socket` em `domain/` —
e ele está certo: essa separação é o que permite testar a política inteira
contra literais de endereço, sem rede.

---

## D-016 — Cross-validation compara identidade de achado, não contagem

**Ambiguidade.** A comparação por contagem de CRITICAL/HIGH já existia e
funcionava para o caso óbvio (0 vs 5).

**Decisão.** Comparar conjuntos de `CVE|pacote` por faixa de severidade, e
classificar o desfecho em `AGREEMENT` / `MINOR_DIVERGENCE` /
`MATERIAL_DIVERGENCE` / `NO_SECOND_SCANNER`.

**Motivo.** Contagem aceitava um caso que não deveria: dois scanners
reportando **um** CRITICAL cada, para CVEs completamente diferentes,
concordavam perfeitamente na aritmética enquanto descreviam imagens
diferentes. A versão está no `AUDIT.md` (F12) e o caso vira teste.

**Consequência registrada.** Divergência *menor* passou a existir como
categoria própria: duas bases de vulnerabilidade legitimamente diferem nas
margens, e chamar isso de "disputado" faria toda imagem parecer contestada.
Ela não refuta o resultado — só impede que a confiança chegue a `HIGH`.
`scan_divergence`, que a tabela e os exporters já liam, continua reservado ao
caso material.

---

## D-017 — O que é evidência é redigido, não só o que é log

**Ambiguidade.** O mascaramento de segredos já existia e era bom; morava
dentro do sink de log.

**Decisão.** Extrair para `infrastructure/redaction.py` e aplicar também aos
artefatos brutos de scan e ao manifesto.

**Motivo.** O log é o arquivo que ninguém abre; a evidência é o arquivo que
as pessoas anexam a ticket e colam em chat. Um scanner que falha um pull
autenticado ecoa a requisição que tentou, cabeçalhos inclusos — e isso ia
para o disco sem passar por padrão nenhum. Um redator, duas portas.

**Consequência registrada.** A redação não pode destruir diagnóstico: há
teste afirmando que CVE, pacote, versão instalada e versão corrigida
sobrevivem intactos.
