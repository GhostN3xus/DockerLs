# Changelog

Todas as mudanças relevantes do DockerLs são documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
e este projeto segue o [Versionamento Semântico](https://semver.org/spec/v2.0.0.html).

## [Não lançado]

### Adicionado

- **Um contrato de exit code documentado** (`dockerls/exit_codes.py`, seção
  "Exit codes" no README), aplicado em toda a CLI: `0` sucesso, `1` erro de
  execução (dependência ausente, rede, Dockerfile inexistente, erro do `docker
  build`), `2` política violada (validação com `errors > 0`, `--fail-on`
  acionado). Antes os números eram literais espalhados pelos comandos e não
  concordavam entre si — `build --validate-only` devolvia `2` para uma falha
  que o teste esperava como `1`, e nada estava escrito em lugar nenhum. A
  distinção entre `1` e `2` é o que permite a um pipeline separar "o scanner
  não rodou" de "a imagem reprovou".
- **`dockerls analyze --wide`**, que renderiza a tabela de vulnerabilidades na
  largura que ela pedir, sem truncar coluna alguma.
- **`dockerls build --list-templates`**, que expõe os templates hardened
  aceitos por `--base`. `list_templates()` existia na interface de domínio
  desde o início e nada o chamava.
- Documentação de `build` e `analyze-dockerfile` no README — os dois comandos
  eram inteiramente ausentes dele.

- **Uma proteção estrutural contra a classe de bug que continuava
  reaparecendo** (`tests/unit/test_no_dead_configuration.py`). Cinco vezes esta
  base de código entregou algo declarado, documentado e nunca alcançado em
  tempo de execução, e duas vezes a própria correção foi parcial. Pegar isso
  lendo o código já falhou repetidamente, então virou teste: todo campo de
  `Settings` precisa ser lido fora de `settings.py`, todo símbolo público
  precisa ser alcançável a partir de algum ponto do pacote, e nenhum módulo
  pode ficar órfão. Ele encontrou mais oito casos já na primeira execução.

### Corrigido (auditoria completa: o hardening que nunca era aplicado)

- **`--hardened`/`--base` nunca leram os templates versionados no repositório**
  (`infrastructure/dockerfile_validator.py`). `TEMPLATES_DIR` subia dois níveis
  a partir de `dockerls/infrastructure/` e reentrava em `infrastructure/
  templates`, resolvendo para `<raiz-do-repo>/infrastructure/templates` — um
  diretório que nunca existiu, e que numa instalação por wheel apontava para
  dentro de `site-packages/`. `exists()` dava `False` em toda execução, então
  os três templates caíam num gerador genérico que abria com
  `FROM <base>:latest`: a ferramenta reprovava base flutuante nas imagens dos
  outros (regra DF001) e emitia uma na própria saída "hardened". Esse gerador
  foi removido; uma base sem template agora falha alto, dizendo quais existem.
- **Os templates não iam para a wheel.** São arquivos de dados, e
  `packages.find` sozinho não os inclui: `build --hardened` funcionava num
  checkout e falhava a partir de um `pip install`. Declarados em
  `[tool.setuptools.package-data]`.
- **`list_templates()` anunciava `java`**, para o qual nunca houve arquivo.
  `--base java` caía calado numa base diferente da pedida; agora a lista é
  derivada do que existe em disco e `--base` é validado antes do build.
- **O template Go rodava como root** (`FROM scratch` sem `USER`) e trazia um
  `HEALTHCHECK ... || exit 0` — inerte na forma exec e, se valesse, um portão
  que nunca reprova. Corrigidos para `USER 65534:65534` e healthcheck real.
- **`FROM scratch` era reportado como tag flutuante** (severidade HIGH). É a
  imagem vazia embutida no Docker: não tem tag alguma para pinar. A regra
  reprovava justamente os Dockerfiles mais enxutos que existem.
- **`USER 0` e `USER 0:0` passavam na regra `non_root_user`**, que só comparava
  com a string `"root"`. Um container rodando como uid 0 recebia PASS.
- **Uma diretiva final terminada em `\` desaparecia** do parser: um `RUN sudo
  ...` na última linha do arquivo nunca era verificado. Os números de linha
  relatados passam a apontar para o início da diretiva, não para o fim.

### Corrigido (auditoria completa: robustez, concorrência e segurança)

- **Referências que na verdade eram flags do scanner passavam pela validação**
  (`utils/validation.py`). O hífen é legal no meio de um nome, então
  `--ignore-unfixed` ou `--offline-scan` satisfaziam o padrão e chegavam ao
  `trivy`/`grype` como opção em vez de alvo — controle sobre como, ou se, o
  scan rodava, a partir de uma referência vinda de variável de CI.
- **Um keyring quebrado derrubava qualquer comando** (`utils/auth.py`). O
  backend SecretService é uma extensão Rust: quando a instalação está
  quebrada ele levanta `pyo3_runtime.PanicException`, que herda de
  `BaseException` e portanto escapava do `except Exception`. Ler credenciais
  opcionais nunca pode abortar a execução; `KeyboardInterrupt` e `SystemExit`
  seguem propagando.
- **Uma falha de cache descartava um scan válido**
  (`use_cases/recommend_images.py`). O erro de escrita subia até o handler que
  reporta falhas de *scan*, então uma imagem inteiramente escaneada e
  pontuada era registrada como `ERROR`/não verificada — bastava o SQLite estar
  travado, o que é rotina sob a concorrência que este caso de uso cria.
- **Rajada de requisições idênticas contra CISA KEV e endoflife.date.** Os
  memos só fechavam a janela *depois* da resposta chegar, e `recommend`
  enriquece todas as tags em paralelo: uma execução de 100 tags disparava 100
  downloads simultâneos do catálogo KEV (megabytes) e até 200 consultas
  idênticas ao endoflife.date — a rajada que provocava o rate limiting e fazia
  tags do mesmo produto receberem vereditos de EOL diferentes na mesma
  execução. Serializados por lock, com dupla checagem.
- **Corrida na escrita do cache SQLite** (`cache/sqlite_cache.py`): o
  select-then-insert tinha janela real para duas threads inserirem a mesma
  chave única. Trocado por um upsert atômico (`ON CONFLICT DO UPDATE`).
- **Injeção de HTML no relatório de build** (`cli/commands/build.py`). `--tag`,
  o caminho do Dockerfile e o tier eram interpolados crus na página; uma tag
  como `x"><script>` transformava um relatório que alguém abre no navegador em
  vetor de execução. O caminho `export --format html` já escapava — este não.
- **`"metrics": null` do Grype quebrava o parse inteiro** de um scan bom.
- **Escritas de arquivo sem tratamento de erro** (`build --report`,
  `build --output`, `sbom --output`) devolviam traceback em vez de mensagem.
- **`search` e `sbom` respondiam com stack trace** a uma referência malformada,
  enquanto todos os outros comandos já reportavam mensagem.
- **`advisor --workers` tinha default fixo `10`**, que anulava
  `Settings.workers` — a mesma classe de configuração morta já corrigida no
  resto da CLI. E um `--format` desconhecido caía calado na tabela do Rich,
  entregando prosa decorada a quem esperava JSON.
- `DockerHubClient.authenticate()` tratava um 200 com corpo não-JSON (portal
  cativo, página de erro de proxy) como exceção não capturada.
- Um `.dockerignore` presente mas ilegível derrubava a validação inteira por
  causa de um check opcional; agora é reportado como SKIP.

### Removido

- Quatro pacotes vazios e sem referência alguma (`dockerls/models/`,
  `repositories/`, `scanners/`, `services/`) — restos de uma estrutura que
  nunca foi usada.
- `Dockerfile.hardened` na raiz do repositório: saída gerada pelo próprio
  caminho de código defeituoso acima, versionada por acidente, com
  `FROM node:latest` e reprovando nas regras da própria ferramenta. Adicionado
  ao `.gitignore`, junto com `logs/` e `.dockerls/` — e o `.gitignore` estava
  literalmente embrulhado numa cerca de markdown (```` ``` ````).
- `dockerls.egg-info/` do controle de versão: metadado de build, já declarado
  em `.gitignore` mas versionado mesmo assim, que reaparecia como ruído em
  todo diff depois de qualquer `pip install -e`.

### Corrigido (revisão final: veredito falso-positivo de segurança)

Seis defeitos da mesma classe, a pior possível numa ferramenta de segurança:
**dizer que está seguro quando não está**. Um falso FAIL custa o tempo de
quem lê; um falso PASS entrega a imagem em produção com o carimbo da
ferramenta.

- **O fallback do Grype devolvia um scan zerado.** O código era
  `return ScanResult(scan_tool="grype")` sob um comentário `# Parse similar
  ao Trivy...`. Numa máquina sem Trivy e com Grype — a configuração de
  fallback que a própria ferramenta anuncia — **todo build era reportado com
  zero vulnerabilidades** e `--fail-on critical` nunca reprovava nada. O
  parser foi implementado (incluindo a faixa `NEGLIGIBLE`, que só o Grype
  tem e que virava `UNKNOWN`).
- **`--fail-on` passava em silêncio quando o scan não rodava.** Sem scanner
  instalado, `scan_result` era `None`, a condição do portão era pulada e o
  build terminava com exit 0. Um portão que não pôde ser avaliado não é um
  portão aprovado: agora é erro de execução (exit 1).
- **`--fail-on medium` e `--fail-on low` nunca reprovavam.** Só `critical` e
  `high` eram tratados; o resto caía num `return False`. Os quatro níveis
  agora funcionam, cada um reprovando também o que é pior que ele, e um
  limiar desconhecido é rejeitado na CLI antes do build começar em vez de
  virar um portão aberto que parece fechado.
- **`non_root_user` dava PASS num container que sobe como root.** A regra
  aceitava qualquer `USER` do arquivo, então um `USER node` num estágio de
  build satisfazia a verificação enquanto o estágio final rodava como root.
  O parser passou a rastrear estágios e resolver o estágio final, inclusive
  seguindo a herança de `FROM <alias>`.
- **`minimal_base` dava PASS com um runtime gordo.** Mesmo defeito: um
  builder em Alpine fazia um runtime em Ubuntu passar. Agora avalia a base
  do estágio final.
- **`secrets_not_in_env` não via a maioria dos segredos.** A regex
  `^ENV\s+(\S+)=(.*)$` lia só o primeiro par de uma linha, então
  `ENV NODE_ENV=production DOCKER_TOKEN=...` passava batido, e a forma
  legada `ENV KEY value` não casava com nada — nunca era verificada. As duas
  formas do Docker agora são cobertas.
- **`shell_usage` era um check que sempre passava** — não olhava nada,
  apenas adicionava um `PASS` incondicional. Uma regra assim é pior que
  regra nenhuma: afirma ao usuário que o ponto foi verificado e ainda infla
  o score. Agora verifica de fato a forma do `CMD`, e devolve `SKIP` quando
  não há o que verificar. `entrypoint_exec_form` também virou `SKIP`
  explícito em vez de sumir da tabela.

- **O cache guardava supressões de CVE já revogadas.** As regras de ignore e
  o enriquecimento de threat intel são aplicados *antes* de gravar o
  `ImageAnalysis`, mas a chave era só a referência da imagem. Um CVE que
  deixava de ser ignorado — porque a regra foi removida, ou porque o
  `expires` dela venceu — continuava suprimido do score e da tabela até o
  TTL expirar (24h no padrão). O próprio arquivo de ignore promete que uma
  isenção vencida deixa de valer, e o cache desfazia essa promessa em
  silêncio. A chave agora carrega um fingerprint das entradas que mudam a
  análise.
- **O sinal de EPSS sumia nas imagens que mais precisavam dele.** Todos os
  CVEs iam num único GET, e a API do FIRST pagina o resultado — de 200 CVEs
  voltava calada só a primeira página. Quanto mais CRITICAL/HIGH a imagem
  tinha, mais sinal se perdia. Agora vai em lotes, com `limit` explícito em
  vez de confiar no default do serviço, e um lote que falha não descarta os
  que já vieram.
- **Vereditos de EOL inconsistentes dentro da mesma execução.** Um 404 do
  endoflife.date (produto fora do catálogo) não era cacheado, então cada uma
  das ~100 tags repetia a consulta perdida — duas, contando `is_eol` e
  `is_lts`. O volume provocava rate limiting, e aí parte das tags recebia
  dados e parte recebia lista vazia: tags do mesmo produto saíam com
  vereditos de EOL diferentes na mesma tabela. O 404 passou a ser cacheado
  (resposta definitiva); falhas transitórias continuam não sendo.
- **Candidatos promovidos escapavam da cross-validation.** Ela rodava sobre
  o top N *antes* do filtro de tags no registry, então um candidato
  promovido para o lugar de um descartado entrava na tabela sem nunca ter
  passado pelo segundo scanner — com a pontuação apresentada sem contestação
  justamente por não ter sido checada, que é o oposto da garantia descrita
  no README. A ordem foi invertida: filtra as tags primeiro, cross-valida
  quem sobrou. De quebra, deixa de gastar um scan secundário em quem vai
  cair.

### Alterado

- **`--push` passou a funcionar.** A flag era aceita e silenciosamente
  ignorada. Agora publica a tag depois de um build bem-sucedido — e depois
  dos portões, porque publicar uma imagem que reprovou no scan derrota o
  propósito de ter portão.
- **`--config` foi removida.** Era aceita, não tinha formato definido e
  nada a consumia.

### Corrigido (auditoria: o que é afirmado versus o que o código faz)

- **`build --validate-only` não imprimia nada de útil.**
  `_format_validation_response()` descartava o resultado da validação e
  devolvia só `success` e `exit_code`, então a CLI imprimia literalmente
  `None` — sem tabela de checks, sem dizer qual regra falhou, em sucesso e em
  falha. Agora a resposta carrega o `DockerfileValidationResult` completo
  (checks, contagens, score) mais um resumo textual das regras violadas em
  `error`, e a CLI renderiza a **mesma** tabela que `analyze-dockerfile`,
  extraída para `dockerls/cli/rendering.py` em vez de duplicada. Em
  `--ci-mode` a saída é JSON estruturado em stdout, sem cores e sem tabela, e
  o relatório entra também quando a validação reprova. Nenhum caminho imprime
  `None`.
- **Uso normal da CLI vazava log `INFO` (e `DEBUG`) no stderr.** `build` nunca
  tocava em `Settings`, então rodava com o sink padrão do loguru ainda
  ligado — que despeja tudo a partir de DEBUG no terminal. A configuração de
  logging virou um callback de raiz do Typer, que roda antes de qualquer
  subcomando, e o sink de console tem piso `WARNING` independente de
  `DOCKERLS_LOG_LEVEL`; `--verbose` o reabre no nível configurado.
- **Uma validação reprovada não barrava o build.** O portão era
  `if not validation_result`, e um objeto é sempre verdadeiro, então a
  condição nunca disparava: o build seguia adiante com o Dockerfile reprovado.
  Agora `errors > 0` barra o build (com `--force` para ignorar), e uma falha
  em *rodar* a validação (Dockerfile inexistente) é `1`, não `2`.
- **`--fail-on` devolvia `1`** para uma imagem que reprovou no scan, o mesmo
  código de uma falha de infraestrutura. Passou a devolver `2`.
- **O relatório de build lia `analysis.recommendations`**, atributo que
  `DockerfileAnalysis` nunca teve. Só não explodia porque `analysis` era
  `None` em todo teste que exercitava esse caminho. As recomendações vêm das
  sugestões de hardening.
- **`_generate_hardened_dockerfile()` escrevia arquivo direto do caso de
  uso**, furando a interface `HardeningTemplateProvider`. A geração passou
  para trás de `generate_hardened_dockerfile()` na infraestrutura — que
  existia e nada chamava. Escrita em disco é responsabilidade de
  infraestrutura.
- `datetime.utcnow()` (deprecado, sem timezone) e `subprocess.os.environ`
  (acesso a `os` por dentro de outro módulo) em `build_image.py`.
- **Todo `subprocess` invocava o binário pelo nome puro** (`docker`, `trivy`,
  `grype`, `git`), entregando a escolha do que executar ao `$PATH` — qualquer
  diretório gravável mais cedo na ordem de busca decidia. É PATH hijacking, a
  mesma classe de achado que esta ferramenta reporta nas imagens dos outros, e
  um scanner de segurança é um alvo especialmente bom porque é o veredito dele
  que o pipeline confia. Agora tudo passa por `resolve_executable()`
  (`dockerls/utils/executables.py`), que resolve para caminho absoluto via
  `shutil.which` e falha nomeando a ferramenta ausente.
- **Dois `try/except/pass` silenciosos** em `build_image.py` engoliam
  exatamente o erro que se quer ver quando o metadado do relatório sai vazio.
  Passaram a logar em DEBUG, com a exceção capturada estreitada.
- **`analyze-dockerfile --format json` emitia JSON inválido** num terminal
  estreito: a saída ia pelo console do Rich, que quebra a linha na largura do
  terminal, e uma quebra no meio de uma string do documento o torna
  imparseável. Em 80 colunas era o caso comum. Passou a sair por
  `typer.echo`. (`recommend` e `advisor` já haviam sido corrigidos com
  `soft_wrap=True`; este ficou para trás.)
- **A tabela do `analyze` truncava o ID da CVE** num terminal de 80 colunas
  (`CVE-2026…`), que é justamente o campo que não pode ser encurtado — sem
  ele o achado não é consultável em lugar nenhum. A coluna passou a reservar
  largura para `CVE-YYYY-NNNNN`, e pacote/versões viraram as colunas
  flexíveis que cedem espaço. De quebra, a tabela deixou de ser cortada na
  borda direita quando não cabia.
- **Os testes de `build_image` mockavam a camada errada.** Os fixtures
  faziam `validator.validate()` devolver um objeto no formato de
  `AnalyzeDockerfileResponse`, mas a interface devolve um
  `DockerfileValidationResult` direto — e como o caso de uso instancia um
  `AnalyzeDockerfileUseCase` internamente, esse retorno era envelopado numa
  segunda camada e `response.validation.errors` caía num `MagicMock`, que
  nunca é igual a `0`. Todo cenário "sem erros" chegava reprovado. Os
  fixtures passaram a devolver os tipos de domínio corretos.
- `--hardened --validate-only` deixou de ser esperado escrevendo em disco:
  dry-run não tem efeito colateral. O teste antigo cobrava o oposto; agora
  há um caso verificando que **nada** é escrito com `--validate-only` e
  outro, sem a flag, verificando a geração de verdade.

- **`logout` não existia**, então `login` conseguia armazenar credenciais sem
  nenhuma forma suportada de removê-las, e `clear_credentials` era inalcançável.
- **`search` passava por cima da camada de aplicação** e falava direto com um
  repositório, deixando `SearchImagesUseCase` órfão. Agora ele passa pelo seu
  caso de uso como todos os outros comandos.
- **`SecurityTier.production_ready` é calculado pelo domínio e carregado em
  `ImageAnalysis`**, então a CLI e o `--format json` afirmam o veredito do
  domínio em vez de re-derivar a regra a partir da letra do tier.
- Removidos cinco símbolos que nada alcançava: `build_search_use_case` (morto
  depois que `search` passou a ignorá-lo), `RichScanObserver.failed`,
  `DockerImage.is_slim`, `ScanResult.is_usable` (substituído por
  `is_verified`), `EvidenceStore.root` e `with_retry` — este último adicionado
  neste mesmo branch e nunca usado.

- **`export` repetia o bug de configuração sombreada** que havia sido corrigido
  apenas em `recommend`: seu `--workers` carregava um default fixo de 10 e ele
  nunca passava limite de tags, então `DOCKERLS_WORKERS` e `DOCKERLS_MAX_TAGS`
  não tinham efeito nenhum ali. Ele também escrevia em disco sem tratamento de
  erro, então um destino não gravável produzia um traceback. Agora delega os
  dois à configuração, cria diretórios pai ausentes e reporta falha de escrita
  como mensagem com saída 1.
- **`cache clear` / `cache cleanup` não tinham testes nem tratamento de erro.**
  Um banco de cache corrompido derrubava justamente o comando que o usuário
  procura para consertá-lo. Erros de armazenamento agora são reportados com
  saída 1.

- **Um rate limit sustentado do Docker Hub derrubava o comando.** O decorador
  `@retry` usava o default do tenacity, então esgotar as tentativas levantava
  `tenacity.RetryError` — que *não* é um `httpx.HTTPError`, de modo que os
  blocos `except httpx.HTTPError` em `search_tags` e `tag_exists` nunca o
  capturavam. A política de retry agora relança o erro original, e esses
  handlers degradam para resultados parciais como foram escritos para fazer. O
  teste anterior verificava `RetryError` e portanto codificava o bug.
- **As três configurações sombreadas restantes estão conectadas.**
  `cache_ttl_seconds`, `retry_max_attempts` e `retry_backoff_base` ainda não
  eram lidos por ninguém: o TTL era um `86400` fixo e a política de retry vivia
  em um decorador avaliado uma única vez na importação, onde nenhuma
  configuração jamais chegaria. A política agora é construída por chamada a
  partir das settings. Adiciona `tag_cache_ttl_seconds`, que antes era um valor
  fixo de 6 horas.
- **O `mypy strict` era nominal.** O `pyproject.toml` declarava `strict = true`
  enquanto tolerava 20 erros, 13 deles do tipo "cannot subclass BaseModel",
  vindos da ausência do plugin do pydantic. Com `plugins = ["pydantic.mypy"]` e
  `types-PyYAML`, a base de código passa na checagem de tipos sem erros: de 20
  para 0. O CI roda `python -m mypy` para que o plugin seja resolvido no mesmo
  interpretador.

- **Nenhum CI jamais havia rodado neste repositório.** Todos os quatro
  workflows disparavam em `pull_request: branches: [main]`, e não existe branch
  `main` — o default é `claude/docker-secure-finder-q7ikdh`. Lint, mypy e a
  matriz de testes nunca haviam executado em um único commit ou pull request,
  então toda afirmação de qualidade se apoiava apenas em execuções locais. O
  filtro de branch foi removido do `pull_request` (dispara em qualquer base e
  sobrevive à renomeação do branch default), `push` ignora branches do
  dependabot, e um grupo de concorrência colapsa as execuções duplicadas de
  push/PR.
- **A integração com o NVD foi removida em vez de anunciada.** `NVDClient` só
  era instanciado em testes e nada sob `dockerls/` o importava, então
  `NVD_API_KEY` nunca teve efeito algum. Seu único sinal real — status de
  exploração conhecida — já é fornecido pelo `ThreatIntelClient` (CISA KEV +
  EPSS), que *está* conectado e testado; conectar o NVD também teria adicionado
  uma dependência de rede redundante só para tornar verdadeira uma linha de
  documentação. O módulo, sua configuração e suas entradas no README foram
  removidos. Ele continua no histórico do git caso venha a ser desejado.
- **`health` sondava um serviço que a ferramenta não usa mais e deixava de fora
  os que ela usa.** Agora verifica Docker Hub, Chainguard, Distroless,
  endoflife.date, CISA KEV e EPSS — os catálogos que alimentam o pipeline de
  scan e os feeds que ponderam a pontuação.

- **A ocultação de credenciais vazava em 10 de 17 formatos realistas de log.**
  O padrão de chave/valor exigia que o nome da chave fosse seguido
  *imediatamente* por `=` ou `:`, e toda linha em formato JSON tem uma aspa no
  meio (`"token": "..."`) — ou seja, os formatos que um cliente HTTP mais
  provavelmente produz passavam direto. A ocultação agora cobre JSON (aninhado,
  compacto, com aspas simples, multilinha), TOML, querystrings, corpos
  multipart, userinfo em URL, `curl -u`, reprs de `Settings(...)` e esquemas de
  autenticação, além de formatos de credencial autoidentificáveis (PAT do
  Docker, token do GitHub, JWT, chave AWS, token do Slack) que aparecem sem
  chave alguma. São 60 casos adversariais em `test_secret_masking.py`, cada um
  verificando que o segredo está *ausente*, e não que alguma forma mascarada
  está presente.
- **`health` reportava a API do Docker Hub como degradada em toda execução
  saudável** — ela sondava `https://hub.docker.com/v2/`, que responde 404 por
  design. Um alarme sempre ligado não informa nada. Ela também sempre saía com
  0, então não podia servir de gate para nada; agora sai com 1 quando qualquer
  serviço está inacessível ou retorna status de erro.
- **A penalidade por idade não tinha teto**, crescendo um ponto por ano, então
  uma imagem de 10 anos perdia tanto quanto duas descobertas HIGH só por estar
  desatualizada. Limitada a 3 pontos, onde ainda consegue ordenar imagens
  igualmente limpas sem competir com severidade medida.

Uma auditoria de cada afirmação do README/CHANGELOG contra o código que a
implementa, verificando que cada uma é alcançada no caminho real de execução.
Achados:

- **A configuração documentada não fazia nada.** `Settings` declarava
  `max_tags`, `workers`, `max_critical`, `max_high` e `max_medium`, e o README
  documentava `DOCKERLS_<SETTING>` e `config.toml` como a forma de alterá-los —
  mas a CLI carregava defaults fixos de `typer.Option` que sombreavam `Settings`
  por completo. O próprio exemplo do README (`DOCKERLS_MAX_TAGS=200`,
  `max_tags = 200` no config.toml) era um no-op. As flags agora têm default
  `None` e caem para o valor configurado; uma flag explícita continua vencendo.
  Coberto por `test_settings_are_wired.py`, que falha em 11 testes contra o
  código anterior.
- **`validate_threshold` nunca era chamada.** `--max-critical -5` e
  `--max-medium 999999` eram aceitos silenciosamente. Os limiares agora são
  validados, e um valor inválido imprime uma mensagem e sai com 1 em vez de
  levantar um traceback.
- **`SecurityTier.production_ready` nunca era lido** e o "Tier B = condicional"
  vivia apenas no README, então uma linha Tier B no terminal não trazia
  nenhuma indicação de que precisa de revisão humana. A CLI agora imprime uma
  seção `Requires review` nomeando cada imagem afetada.
- **A integração com o NVD não está conectada a nenhum comando** — `NVDClient`
  só é instanciado em testes, então `NVD_API_KEY` não tinha efeito apesar de o
  README anunciar um benefício de rate limit. Documentado como reservado em vez
  de removido; conectá-lo é um trabalho separado.
- O exemplo `--max-medium 10` do README parecia contradizer o default
  documentado de 5; ele é uma sobrescrita, e agora diz isso.

Continuação da reformulação do `recommend`, motivada por uma execução real de
`dockerls recommend node`.

### Corrigido
- **A pontuação de segurança não conseguia diferenciar imagens.** Os bônus
  somavam +19 contra uma base de 100, então qualquer coisa razoavelmente
  decorada batia no teto: uma imagem limpa, uma com 1 HIGH, uma com 2 HIGH e
  uma com 5 MEDIUM reportavam exatamente `100.0` — o número afirmava que uma
  imagem vulnerável era tão segura quanto uma limpa. A pontuação agora começa
  em 96 com bônus qualitativos limitados a 4,0, estritamente abaixo da
  penalidade de um único HIGH, de modo que nenhuma combinação de "oficial +
  minimal + assinada + LTS + recente" consegue elevar uma imagem com um HIGH ou
  CRITICAL a mais acima de uma mais limpa. Os bônus ainda podem superar um ou
  dois MEDIUM, o que é intencional. O bônus redundante de "zero
  vulnerabilidades" foi removido — zero descobertas já significa zero
  penalidade.
- **A validação cruzada estava patologicamente lenta** (~4m12s para cinco
  imagens). Duas causas, ambas tratadas: o Grype revalida seu banco de
  vulnerabilidades a cada invocação, então o lote agora roda `grype db update`
  uma vez e escaneia com `GRYPE_DB_AUTO_UPDATE=false`; e as validações rodavam
  em um `for` sequencial apesar de serem independentes, então agora rodam
  concorrentemente sob um teto de workers
  (`DOCKERLS_CROSS_VALIDATE_WORKERS`, default 5).
- Imagens de registries que listam apenas nomes de tag eram cobradas com a
  penalidade máxima de idade e ficavam sem o bônus de recência por causa de
  metadados que o registry simplesmente não publica. A idade agora só move a
  pontuação quando a fonte de fato reportou uma data.

### Adicionado
- **Catálogos endurecidos e gratuitos são pesquisados junto com o Docker Hub**:
  Chainguard (`cgr.dev/chainguard/<imagem>`) e Distroless
  (`gcr.io/distroless/<imagem>`). Suas tags passam pelo mesmo pipeline de scan,
  então uma imagem endurecida vence por vulnerabilidades medidas e não por
  reputação. Uma nova coluna `Source` nomeia a origem de cada linha, e o resumo
  da execução lista quais catálogos responderam. `--no-hardened` desativa.
- As listagens de registry são filtradas para imagens de verdade: artefatos
  cosign `.sig`/`.att`/`.sbom` (~1000 por repositório do Chainguard), aliases
  de arquitetura única e duplicatas fixadas em commit são descartados.
- "No image found matching baseline" agora imprime os critérios exatos que não
  foram atendidos.
- O bloco `Details` dá a cada imagem seus próprios caminhos de evidência,
  marcando `(shared digest)` onde tags que compartilham um manifesto foram
  escaneadas uma única vez.
- `AnalysisResult.sources_searched` e `AnalysisResult.baseline` expõem os dois
  fatos ao `--format json`.
- Suíte de aceitação (`tests/acceptance/`) verificando o orçamento
  ponta-a-ponta (<30s para cinco imagens), uma única exibição de progresso sem
  vazamento para o fluxo de resultados, evidência por imagem em disco, e que
  ambas as fontes endurecidas são consultadas.

### Alterado
- A exibição de progresso é renderizada em **stderr**, os resultados em
  **stdout**, de modo que os dois fluxos não podem se intercalar e redirecionar
  o stdout mantém o spinner no terminal. O observer é de uso único e rejeita
  reentrada; um teste verifica que o pacote contém exatamente uma exibição ao
  vivo do Rich.
- A verificação de tags foi generalizada para além do Docker Hub: cada tag é
  confirmada pelo registry que a possui. A coluna `Hub` da tabela agora é `Tag`.



Reformulação do `dockerls recommend`: saída de terminal limpa, causa raiz dos
erros de scan do Trivy removida, e nenhuma imagem recomendada sem prova de que
foi escaneada e de que sua tag existe.

### Corrigido
- **Contenção de lock no cache do Trivy (causa raiz dos erros de scan).** Scans
  paralelos compartilhavam um único `--cache-dir` e disputavam o lock exclusivo
  do Trivy, fazendo com que os perdedores saíssem com código diferente de zero
  com `cache may be in use by another process: timeout`. O banco agora é baixado
  uma vez no início, e então cada worker concorrente recebe seu próprio
  diretório de cache com o banco vinculado por hardlink (sem cópias de centenas
  de MB), desmontado ao fim da execução. Onde o hardlink não está disponível, o
  pool degrada para um único slot compartilhado, o que serializa os scans em vez
  de deixá-los colidir.
- A ocultação de segredos vazava credenciais quando um esquema de autenticação
  estava aninhado em um par chave-valor: em `auth: Bearer <token>` o padrão de
  chave-valor consumia apenas a palavra `Bearer`, deixando o token exposto. Os
  padrões de esquema agora rodam primeiro.
- Um acerto de cache não é mais tomado como prova de um scan bem-sucedido; uma
  análise em cache cujo scan não está verificado é descartada e reescaneada.

### Adicionado
- **Portão de verificação.** `ScanResult.is_verified` exige um scan concluído
  (`OK`) com timestamp. Qualquer outra coisa — erro, timeout, parcial, ou um
  placeholder construído por default — é reportada em uma seção separada
  `Unverified (technical error)` sem pontuação e sem tier, e `_assert_verified`
  levanta `UnverifiedRecommendationError` se uma imagem não verificada chegar
  aos resultados.
- **Validação cruzada entre scanners.** Os principais candidatos são
  reescaneados com o scanner secundário; uma divergência material nas contagens
  de CRITICAL/HIGH substitui a pontuação numérica por `!disputed` mais a
  discrepância.
- **Evidência de scan.** O JSON bruto do scanner é gravado em `.dockerls/scans/`,
  com um manifesto por execução ligando cada pontuação exibida à saída de onde
  ela veio (`DOCKERLS_EVIDENCE_DIR`).
- **Links do Docker Hub.** `build_dockerhub_url()` emite a forma correta para
  imagens oficiais (`/_/<repo>?tab=tags&name=<tag>`) e de terceiros
  (`/r/<ns>/<repo>/tags?name=<tag>`), pulando registries fora do Hub. As tags
  são confirmadas contra a API do Hub (com cache TTL para ficar dentro do limite
  anônimo de requisições) e descartadas se confirmadamente ausentes.
- Novas flags: `--verbose`, `--no-progress`, `--no-cross-validate`,
  `--no-hub-check`. Novas configurações: `DOCKERLS_LOG_DIR`,
  `DOCKERLS_EVIDENCE_DIR`, `DOCKERLS_TRIVY_CACHE_DIR`,
  `DOCKERLS_CROSS_VALIDATE`, `DOCKERLS_VERIFY_HUB_TAGS`.

### Alterado
- O logging é somente para arquivo por default (`logs/dockerls_<timestamp>.log`);
  o sink do loguru para stderr foi removido para que nada se intercale com a
  exibição de progresso do Rich. `--verbose` o reativa.
- O progresso do scan é renderizado como uma única linha transitória de spinner
  do Rich (`Scanning node:26.7-slim... [3/24]`), seguida de um resumo da
  execução (`OK 12/24 analyzed | X 12 skipped (technical error)`) antes da
  tabela.
- A tabela de resultados foi estreitada para caber em um terminal de 80 colunas
  sem truncar referências de imagem: as contagens de severidade colapsam em uma
  única célula `C/H/M`, e as URLs completas do Hub são listadas abaixo da tabela
  em vez de dentro dela.
- Esquema de cache elevado para `v2` por causa dos novos metadados de
  verificação.

## [1.1.0]

Rodada de preparação para produção cobrindo correções de corretude, melhorias
funcionais, novos recursos de produção e endurecimento de engenharia.

### Corrigido (bloqueadores)
- Scans que falham ou dão timeout não são mais tratados como imagens "limpas".
  Um `ScanStatus` (OK/ERROR/TIMEOUT/PARTIAL) é rastreado ponta a ponta e o
  `SecurityScore` se recusa a pontuar qualquer coisa que não seja um scan
  OK/PARTIAL.
- A autenticação no Docker Hub agora é de fato usada: `build_repository()`
  carrega as credenciais do keyring e chama `authenticate()`, e o `dockerls
  login` valida as credenciais antes de armazená-las.
- Tags que compartilham o mesmo digest de manifesto são escaneadas uma vez e
  compartilham o resultado, em vez de serem reescaneadas por tag.
- O banco de vulnerabilidades do Trivy é atualizado uma vez por execução e os
  scans individuais passam `--skip-db-update`.
- O cache SQLite não bloqueia mais o event loop (`asyncio.to_thread`); as
  chaves de cache são versionadas por esquema e um payload em cache
  obsoleto/incompatível é tratado como miss em vez de causar um crash.
- A detecção de EOL agora mapeia nomes de imagem do Docker Hub para os slugs
  corretos de produto do endoflife.date e usa comparação de versão ciente de
  SemVer em vez de prefixos ingênuos de string.

### Adicionado / Alterado (recursos funcionais e de produção)
- Cliente do Docker Hub: retry por requisição (não por lote inteiro),
  tratamento de `Retry-After` em 429, degradação graciosa para resultados
  parciais em erros de rede, e relatório multi-arquitetura
  (`available_architectures`).
- A validação de nome de imagem aceita referências por digest e prefixos de
  registry privado com porta.
- Seleção determinística de CVSS (NVD > fabricante > primeiro disponível, CVSS
  v4 preferido sobre v3) tanto no parser do Trivy quanto no do Grype.
- Ocultação completa de segredos nos logs (nenhum valor parcial vazado).
- `recommend`/`advisor` ganham códigos de saída amigáveis a CI, `--fail-on`,
  `--format json` e `--no-color`; `analyze`/`compare` ganham `--no-color`.
- Novo comando `sbom` (CycloneDX/SPDX via Trivy) e `export --format sarif`
  (SARIF 2.1.0).
- Suporte a `.dockerls-ignore.yaml` para ignorar CVEs com justificativa e
  expiração.
- Sinal de threat intel CISA KEV + EPSS incorporado ao `SecurityScore`
  (best-effort, degrada graciosamente se inacessível).
- Imagens de fornecedores endurecidos (Chainguard, Wolfi, Bitnami) contam para
  o bônus de pontuação de "base minimal".

### Engenharia
- `mypy --strict` passa em todo o pacote (não apenas na camada de domínio); os
  ignores genéricos `S603`/`S607` do `ruff` foram removidos em favor de `noqa`s
  estreitos por local de chamada nas duas chamadas de subprocesso comprovadamente
  seguras.
- Suíte de testes expandida para mais de 190 testes cobrindo caminhos de
  erro/timeout do scanner, versionamento de cache, modo de fallback, tratamento
  de resultados parciais em HTTP, parsing de EOL e todos os comandos da CLI;
  cobertura elevada do piso de 80% para ~89%.
- Dockerfile endurecido: imagens base fixadas por digest, Trivy copiado da sua
  imagem oficial em vez de `curl | sh`.
- O workflow de release agora anexa uma atestação nativa de proveniência de
  build SLSA do GitHub e artefatos assinados com Sigstore.
- `__version__` agora lê os metadados do pacote instalado
  (`importlib.metadata`) em vez de uma string mantida à mão.
- Settings migradas para `pydantic-settings` com variáveis de ambiente
  prefixadas com `DOCKERLS_` e um `~/.config/dockerls/config.toml` opcional.
- Suporte a chave de API do NVD (`NVD_API_KEY`) com rate limiting correto (5
  versus 50 requisições/30s).
- Removido o stub da integração com Docker Scout, que nunca foi usado nem
  conectado.

## [1.0.0] - 2024-01-01

### Adicionado
- Lançamento inicial
- Comando `search`: pesquisa tags no Docker Hub
- Comando `recommend`: recomenda imagens seguras com pontuação
- Comando `advisor`: consultor de segurança com planos de remediação
- Comando `analyze`: análise profunda de uma tag específica
- Comando `compare`: comparação lado a lado de imagens
- Comando `export`: exporta relatórios em JSON, CSV, HTML, Markdown
- Comando `login`: autenticação no Docker Hub via keyring
- Comando `doctor`: verificação de dependências do sistema
- Comando `health`: verificação de conectividade com serviços externos
- Subcomandos `cache`: gerenciamento de cache (clear, cleanup)
- Integração com Trivy (scanner primário)
- Integração com Grype (scanner de fallback)
- Integração com Docker Scout (complementar)
- Integração com a API do NVD
- Integração com endoflife.date
- Algoritmo de pontuação de segurança (0-100)
- Classificação em níveis de segurança (S/A/B/C)
- Cálculo de pontuação de remediação
- Fallback inteligente quando nenhuma imagem atende à baseline
- Cache de scan baseado em SQLite com TTL
- Logging estruturado com ocultação de segredos
- Validação e sanitização de entrada
- Dockerfile seguro (multi-stage, não-root, somente leitura)
- Workflows de CI/CD (lint, test, security, CodeQL)
- Configuração do Dependabot
