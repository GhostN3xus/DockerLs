# Desempenho: o que foi medido, onde, e o que é simulado

Três tipos de número, nunca misturados. Todos os scripts estão em `benchmarks/`; os resultados brutos (JSON e Markdown, com versões e ambiente) em `benchmarks/results/`.

| Tipo | Script | O que mede | O que **não** diz |
|---|---|---|---|
| **Simulado** | `bench_pipeline.py`, `bench_profiles.py` | O código real da aplicação (use cases, serviço de medição, cache em camadas, pontuação) ligado a registry/scanner/feeds falsos que dormem por um tempo configurável | Nada sobre a velocidade de qualquer registry, feed ou scanner real. As latências são **entradas**, impressas com o resultado |
| **Real** | `bench_real.py` | Tempo de parede da CLI instalada, com Trivy real e registry real | Só vale para esta máquina e esta rede (abaixo); varia com a carga do registry |
| **Medição pontual** | (comandos citados abaixo) | Custos isolados de uma etapa | — |

Rodar (na raiz do repositório): `python benchmarks/bench_pipeline.py --repeat 7`, `python benchmarks/bench_profiles.py --repeat 7`, `python benchmarks/bench_real.py --repeat 5 --engine both --full-cold` (este último exige `dockerls` e `trivy` no PATH). O benchmark real sempre mede `analyze`, `search` e `recommend`, em estados frios e quentes quando há cache. Cada linha separa tempo total, startup, rede/API, scanner e cache; etapas sobrepostas não devem ser somadas para tentar reconstruir o total.

## Ambiente das medições abaixo

Linux 6.18 (VM), x86_64, 4 CPUs, Python 3.11.15, DockerLs 1.0.16 + as mudanças desta branch, Trivy `Version: dev` (binário local), Grype presente. Rede real; alvo `mirror.gcr.io/library/alpine:3.20` (não sofre o limite anônimo do Docker Hub). Medianas e p95 sobre `n` repetições (com poucas amostras o p95 é simplesmente o máximo; `n` está em toda tabela).

## Real: CLI ponta a ponta (`bench_real.py`, n=5; "cold everything" n=1)

| Cenário | mediana s | p95 s |
|---|---|---|
| `analyze`, tudo frio (store, DB do Trivy baixado de novo) — Python | 15,8 | 15,8 |
| `analyze`, tudo frio — com engine Go presente | 13,5 | 13,5 |
| `analyze amd64`, store frio (DB e camadas do Trivy já em disco) — Python / Go | 5,64 / 5,86 | 5,78 / 6,47 |
| `analyze amd64`, store quente (resultado reaproveitado, `origin: cache`) — Python / Go | 3,05 / 3,19 | 3,39 / 3,28 |
| `analyze arm64`, store frio — Python / Go | 5,99 / 5,93 | 6,41 / 6,30 |
| `compare` de 2 imagens, store frio — Python / Go | 6,78 / 6,44 | 7,58 / 6,66 |
| `compare` de 2 imagens, store quente — Python / Go | 3,05 / 2,81 | 3,28 / 3,21 |

Leituras honestas:

- **Python vs Go não é comparável aqui.** A engine Go entra no caminho em lote (`recommend`, com muitas tags). `analyze` e `compare` de uma ou duas imagens não a usam; as diferenças da tabela são ruído (n=5, um mesmo processo Python nos dois lados). Nenhum ganho da engine Go foi medido neste benchmark. A comparação isolada de orquestração está em `docs/REFERENCE.md#performance` (`bench_fanout.py`, `bench_discovery.py`).
- **Um resultado reaproveitado ainda leva ~3 s.** Medido por partes numa execução quente: ~0,3 s de imports; ~0,24 s carregando o bundle de CA em 8 clientes HTTP (um `SSLContext` por cliente); ~0,75 s de resolução de identidade (HEAD no registry); o resto é chamada de versão dos scanners e avaliação. O que **não** faz mais parte desse custo: a atualização do banco do Trivy (~1,7 s, eliminada antes de `NextUpdate`) e as consultas de fim de vida do `alpine`, que antes davam 301 e não retornavam dado. Esses custos restantes não foram atacados.
- **Compare quente ≈ analyze quente** porque as duas imagens são resolvidas em paralelo e ambas vêm do cache.

## Medições pontuais (esta máquina)

- **Primeiro `analyze` num sistema limpo: ~116 s antes, ~15 s depois** (`time dockerls analyze mirror.gcr.io/library/alpine:3.20 --platform linux/amd64` com diretórios de cache vazios). A causa, medida à parte: `grype db update` num diretório vazio levou **108 s de CPU** (importação do SQLite), contra **7,5 s** do `trivy image --download-db-only`. O banco do Grype era preparado sempre, mesmo em comandos que nunca chamam o Grype; agora é preparado quando o secundário é usado pela primeira vez (fallback, ou validação cruzada do `recommend`). **Consequência:** o primeiro `recommend` num sistema limpo, que faz validação cruzada por padrão, ainda paga esses ~108 s uma vez. Isso não foi remedido depois da mudança.
- Identidade por `HEAD` + mapeamento persistido + GET por digest: um `recommend` real contra o Docker Hub, neste IP, recebeu 429 (mesmo em HEAD) e terminou com identidade não confirmada. Isso é uma limitação do ambiente de teste; a saída diz o motivo.

## Simulado: orquestração (`bench_pipeline.py`, n=5)

Entradas: scan 0,20 s, resolução de identidade 0,03 s, intel 0,05 s (lento: 1,0 s), 4 workers, 6 tags (pequeno) / 36 tags (grande).

| Cenário | mediana s | scans |
|---|---|---|
| recommend 6 tags, cache frio | 0,468 | 6 |
| recommend 6 tags, cache quente | 0,034 | 0 |
| recommend 36 tags, cache frio | 2,019 | 36 |
| recommend 36 tags, cache quente | 0,163 | 0 |
| 36 tags que apontam para 6 digests | 0,596 | **6** (30 duplicatas evitadas) |
| compare de 2 imagens (limite 4) | 0,234 | 2 (concorrência 2) |
| compare de 8 imagens (limite 4) | 0,467 | 8 (concorrência 4) |
| intel saudável / lento (1 s) / indisponível | 0,518 / 1,470 / 0,519 | 6 |
| 3 runs simultâneos, store compartilhado | 0,471 | **18** |

O que a tabela mostra e o que não:

- O reaproveitamento (0 scans no run quente) e a deduplicação por digest (6 scans para 36 tags) são propriedades do código, e reproduzem.
- **3 runs simultâneos escaneiam o triplo**: o single-flight é por processo/serviço, não entre runs independentes; o store persistido evita a repetição só no run *seguinte*. Não há trava de scan entre processos (o que existe entre processos é a exclusão dos slots de cache do Trivy).
- O cenário "intel indisponível" usa um falso que devolve "sem resposta"; a distinção entre ausente / erro / rate limit / inválido está nos testes (`tests/unit/integrations/test_threat_intel_sharing.py`), não é cronometrada.
- A concorrência de scans é limitada (`--workers`) e o scanner falso não consome CPU: os tempos mostram sobreposição de espera, não custo de CPU.

## Simulado: perfis (`bench_profiles.py`, n=7, repositório com 60 tags)

| Perfil | mediana s | scans | pedidos de intel | verificações pendentes |
|---|---|---|---|---|
| `quick` (8 tags, intel só finalistas) | 0,575 | 8 | 12 | 5 |
| `standard` (25 tags) | 1,624 | 25 | 38 | 3 |
| `audit` (todas, 60) | 3,367 | 60 | 90 | 3 |

**Não simulado:** a validação cruzada com o 2º scanner das finalistas (exige um 2º scanner). As "pendentes" de `standard`/`audit` são as que o ambiente falso não realiza (validação cruzada, inspeção). Os valores do `quick` (8 tags, sem validação cruzada, intel só nas finalistas) **foram escolhidos, não otimizados**: só o custo relativo foi medido, num cenário simulado.

## Não medido

- Cenários com **muitas tags reais** e **fontes lentas/indisponíveis/com rate limit reais** (só simulados; o Docker Hub deu 429 no ambiente).
- Execuções simultâneas de **processos** com cache de Trivy compartilhado (a exclusão dos slots é testada com processos reais, o ganho de tempo não foi cronometrado).
- Custo de CPU/memória por etapa em runs grandes; `RunInstrumentation` registra tempo de parede, não consumo de recursos. `compare` ainda não publica tempos por etapa.
- Contagem exata de requisições por fonte durante descoberta composta; o
  tempo total de descoberta é medido, mas hoje conta como uma chamada lógica
  ao registry no `search`.
