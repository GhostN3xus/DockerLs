# Auditoria de evidência — 2026-08

Relatório produzido **antes** de qualquer alteração, conforme a Fase A.
A coluna *Status* foi preenchida depois, quando cada achado foi corrigido. Cada
achado foi verificado no código e, onde marcado *(demonstrado)*, reproduzido
executando o próprio pacote.

O critério que orienta a severidade é um só:

> Uma imagem que não pôde ser medida nunca deve ser apresentada como segura.

Um achado é **crítico** quando a ferramenta afirma segurança sem evidência que
a sustente; **alto** quando ausência de dado é convertida em fato favorável;
**médio** quando a evidência é frágil, contaminável ou irreprodutível.

---

## Sumário

| # | Sev. | Achado | Status |
|---|------|--------|--------|
| F1 | CRÍTICA | `production_ready` não conhece confidence: `PARTIAL` sem achados vira tier A e "production ready" enquanto o confidence diz `UNVERIFIED` | **corrigido** — política central `ProductionReadiness`, único escritor do campo |
| F2 | ALTA | EOL desconhecido é convertido em `False` | **corrigido** — `eol_status` tri-state; `UNKNOWN` não penaliza, não credita e é reportado |
| F3 | ALTA | Feed KEV/EPSS indisponível faz todo CVE virar "não explorado", e o rationale **afirma** "no known-exploited vulnerabilities" | **corrigido** — `kev_status` tri-state; a afirmação só sai sobre achados efetivamente consultados |
| F4 | ALTA | SSRF para loopback, RFC1918 e endpoint de metadados *(demonstrado)* | **corrigido** — `NetworkPolicy` + `HostGuard`, decisão por resolução |
| F5 | MÉDIA | Injeção de markup Rich a partir de texto do scanner *(demonstrado)* | **corrigido** — `cli/text.safe()` nas interpolações de terceiros |
| F6 | MÉDIA | `PARTIAL` recebe score de segurança | **mitigado** — o score continua sendo calculado (relatórios precisam dele), mas nunca é veredito: `PARTIAL` é `UNVERIFIED` e bloqueado por `NOT_MEASURED` |
| F7 | MÉDIA | EPSS binário em 0.5 | **corrigido** — degrau preservado + termo contínuo; monotônico e testado |
| F8 | MÉDIA | `run_capture` sem teto de saída | **corrigido** — 256 MiB por fluxo, excesso vira `INVALID_OUTPUT` |
| F9 | MÉDIA | Evidência bruta sem redação | **corrigido** — redator central aplicado a artefatos e manifesto |
| F10 | MÉDIA | Chave de cache ignora scanner e versão | **corrigido** — identidade do scanner entra no fingerprint |
| F11 | MÉDIA | Versão do scanner nunca registrada | **corrigido** — capturada por execução, no manifesto e no cache |
| F12 | MÉDIA | Cross-validation por contagem | **corrigido** — comparação por identidade (CVE+pacote) e desfecho classificado |
| F13 | BAIXA | `TAG_MOVED` não detectado | **pendente** — a chave por digest já impede servir evidência de outra imagem; falta *reportar* o movimento |

Um achado extra apareceu durante a correção e foi tratado junto:

| F14 | BAIXA | Processo morto por timeout deixava o transporte para o coletor de lixo, e o `__del__` rodava depois do event loop fechar | **corrigido** — `_close_transport` no reap |

---

## F1 — `production_ready` não conhece confidence  *(CRÍTICA)*

**Arquivo.** `dockerls/domain/value_objects/security_tier.py`, `SecurityTier.production_ready`.

**O que faz hoje.**

```python
@property
def production_ready(self) -> bool:
    if self._is_eol:
        return False
    return self._tier in PRODUCTION_READY_TIERS
```

O tier vem do score, e o score vem do scan. Nada nessa cadeia sabe se o scan
foi *concluído*.

**Impacto.** Um scan `PARTIAL` (alvos que não puderam ser inspecionados) com
zero achados nos alvos que puderam produz score alto → tier A →
`production_ready = True`. Ao lado, `confidence` reporta `UNVERIFIED`. A mesma
análise afirma as duas coisas. É exatamente a substituição que o princípio
fundamental proíbe, e está no campo que um portão de CI mais provavelmente lê.

**Proposta.** Criar uma política central `ProductionReadiness` no domínio, que
consuma tier, EOL, confidence, divergência e verificação do scan — e fazer
`ImageAnalysis.production_ready` derivar dela. Regra: qualquer coisa abaixo de
`MEDIUM` de confidence não é production ready, independentemente do tier.

---

## F2 — EOL desconhecido vira `False`  *(ALTA)*

**Arquivo.** `dockerls/integrations/endoflife/checker.py`, `is_eol`/`is_lts`.

Todo caminho de falha — produto não catalogado, versão não extraída, rede
indisponível — retorna `False`. `SecurityScore` recebe `is_eol: bool` e não
distingue "não está EOL" de "não foi possível saber".

**Impacto.** Uma imagem cuja data de fim de vida ninguém conseguiu consultar é
pontuada como se estivesse dentro do suporte, e passa por `production_ready`.
Ausência de evidência tratada como evidência favorável.

**Proposta.** Tri-state. `EOLCheckerInterface` ganha `eol_status()` devolvendo
`Tristate`; `is_eol()` permanece para compatibilidade. `UNKNOWN` não penaliza
(não há evidência de EOL) mas **impede** o topo da confiança e aparece no
rationale — que é a diferença entre "não está EOL" e "ninguém sabe".

---

## F3 — Feed de threat intel indisponível vira "não explorado"  *(ALTA)*

**Arquivos.** `integrations/threat_intel/client.py` (retorna `set()`/`{}` em
qualquer falha) e `application/services/verdict.py:148`.

O enriquecimento faz `exploit_known = cve in kev_ids`. Com o feed fora do ar,
`kev_ids` é vazio e **todo** CVE fica `exploit_known=False`. Em seguida o
rationale imprime, afirmativamente:

```
no known-exploited (CISA KEV) vulnerabilities
```

**Impacto.** A frase mais forte que a ferramenta produz sobre exploração real é
emitida justamente quando ela não conseguiu consultar nada. Pior que o score:
é uma afirmação em linguagem natural que o leitor vai citar.

**Proposta.** Registrar se o feed respondeu. `NOT_LISTED` (consultado, não
consta) ≠ `UNKNOWN` (não consultado). A frase afirmativa só sai no primeiro
caso; no segundo, o texto diz que a inteligência não estava disponível, e o
confidence cai.

---

## F4 — SSRF em referências de imagem  *(ALTA, demonstrado)*

**Arquivo.** `integrations/registry/inspector.py`, `_registry_target`.

Reproduzido com o pacote instalado:

```
169.254.169.254/latest      -> ('169.254.169.254', 'latest')
127.0.0.1:5000/app          -> ('127.0.0.1:5000', 'app')
10.0.0.5:5000/internal/app  -> ('10.0.0.5:5000', 'internal/app')
```

O host só é validado quanto ao *formato*. `RegistryInspector` então emite
`GET https://169.254.169.254/v2/latest/manifests/...`.

**Impacto.** Num runner de CI, uma referência vinda de um PR, de um
`config.toml` ou de uma variável de ambiente transforma o DockerLs num
primitivo de SSRF contra o endpoint de metadados da nuvem e contra serviços
internos. O corpo não volta para o atacante, mas o alcance de rede é dele.

**Proposta.** Uma `NetworkPolicy` explícita, aplicada antes de qualquer
requisição. Padrão: **bloquear loopback e link-local** (169.254.0.0/16 inclui o
endpoint de metadados; nenhum registry público legítimo mora lá) e **permitir
RFC1918**, porque registry interno é caso legítimo e comum — como o próprio
enunciado adverte. Configurável nos dois sentidos, com allowlist de hosts.

---

## F5 — Injeção de markup Rich vinda do scanner  *(MÉDIA, demonstrado)*

Descrições de CVE, nomes de pacote e mensagens de erro do scanner são passados
a `rich` sem escape. Reproduzido:

```
entrada : "[red]FIXED - no action needed[/red] [blink]"
render  : "FIXED - no action needed"      # markup interpretado, não exibido
```

**Impacto.** Quem controla o conteúdo de um advisory upstream — ou os metadados
de um pacote dentro de uma imagem sob análise — controla a formatação do
relatório: pode colorir um achado como benigno, aplicar `[blink]`, ou fabricar
texto que parece anotação da ferramenta. É o único ponto em que dado não
confiável vira instrução de apresentação.

**Proposta.** `rich.markup.escape` em toda interpolação de texto de terceiros,
e teste adversarial fixando o comportamento.

---

## F6 — `PARTIAL` recebe score  *(MÉDIA)*

`SecurityScore.__init__` aceita `OK` **e** `PARTIAL`. Um scan parcial produz
número, tier e — via F1 — veredito. O próprio docstring de
`ScanResult.is_verified` diz que `PARTIAL` é um limite inferior, não uma
medição; o score não respeita isso.

**Proposta.** Não remover a capacidade (relatórios querem mostrar o que foi
achado), mas marcar: o score de um `PARTIAL` nunca é apresentado como veredito,
e a política de production readiness o rejeita.

---

## F7 — EPSS binário  *(MÉDIA)*

```python
penalty += HIGH_EPSS_PENALTY * sum(1 for v if v.epss_score >= 0.5)
```

EPSS 0.97 e EPSS 0.51 custam o mesmo; 0.49 custa zero.

**Proposta.** Preservar o degrau (é o que o operador entende) e somar um termo
contínuo proporcional, mantendo o teto abaixo da penalidade de CRITICAL.

---

## F8 — Saída do scanner sem teto  *(MÉDIA)*

`run_capture` usa `proc.communicate()`, que acumula stdout inteiro em memória.
Um scanner comprometido, ou apenas uma imagem com dezenas de milhares de
achados, é lido sem limite.

**Proposta.** Ler com teto explícito e classificar o excesso como
`INVALID_OUTPUT` — que já é um estado não verificado.

---

## F9 — Evidência bruta sem redação  *(MÉDIA)*

`EvidenceStore._record_scan_sync` faz `path.write_text(raw)`. O mascaramento de
segredos existe, mas só no sink de log. A evidência é o artefato que as pessoas
anexam a tickets.

**Proposta.** Passar o artefato pelo mesmo redator central, sem destruir os
campos de diagnóstico.

---

## F10/F11 — Cache e reprodutibilidade  *(MÉDIA)*

A chave é `analysis:{fingerprint}:{digest|referência}`. O fingerprint cobre
regras de ignore e presença de threat intel; **não** cobre qual scanner rodou,
sua versão, nem a versão da base de vulnerabilidades. Um `dockerls` que trocou
de Trivy para Grype, ou que atualizou a base, serve o resultado antigo dentro
do TTL.

A versão do scanner não é capturada em lugar nenhum, então a análise não é
reconstruível — que é o requisito da Fase 18.

**Proposta.** Capturar identidade do scanner (nome + versão) uma vez por
execução, incluí-la no fingerprint do cache e registrá-la no manifesto.

---

## F12 — Cross-validation por contagem  *(MÉDIA)*

`_describe_divergence` compara `critical_count` e `high_count`. Dois scanners
que reportam **um** CRITICAL cada, mas CVEs diferentes, são classificados como
concordância.

**Proposta.** Comparar identidade de vulnerabilidade (CVE + pacote), classificar
em `AGREEMENT` / `MINOR_DIVERGENCE` / `MATERIAL_DIVERGENCE` / `NO_SECOND_SCANNER`
e alimentar o confidence com a classe, não com um booleano.

---

## F13 — `TAG_MOVED` não é detectado  *(BAIXA)*

A chave de cache por digest já evita servir resultado de outra imagem. O que
falta é *dizer* que a tag se moveu — informação acionável para quem fixou a tag
num Dockerfile.

**Proposta.** Registrar o último digest visto por tag e reportar a mudança.
