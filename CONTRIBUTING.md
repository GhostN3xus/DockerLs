# Política de Segurança

## Versões suportadas

| Versão | Suportada |
|--------|-----------|
| 1.x    | Sim       |

## Reportando uma vulnerabilidade

Se você descobrir uma vulnerabilidade de segurança no DockerLs, por favor reporte de forma responsável.

**Não abra uma issue pública.**

Use o recurso de reporte privado de vulnerabilidades do GitHub neste repositório:
**Security → Report a vulnerability**.

### O que incluir

- Descrição da vulnerabilidade
- Passos para reproduzir
- Avaliação de impacto
- Correção sugerida (se houver)

### Prazos de resposta

- Confirmação de recebimento: até 48 horas
- Avaliação inicial: até 1 semana
- Correção e divulgação: coordenadas com quem reportou

## Design de segurança

O DockerLs segue estes princípios de segurança:

### Validação de entrada

- Todos os nomes de imagem são validados contra um padrão de regex estrito
- Ataques de path traversal são bloqueados
- Injeção de comando é impedida (sem `shell=True`, sem interpolação de strings nos comandos)

### Tratamento de credenciais

- As credenciais são armazenadas no keyring do sistema (nunca em arquivos de texto puro)
- Variáveis de ambiente são suportadas como alternativa
- Todas as credenciais são mascaradas na saída de log
- Bearer tokens e senhas são filtrados do logging estruturado

### Segurança de rede

- Todas as requisições HTTP usam HTTPS
- Timeouts são aplicados em todas as chamadas externas
- A lógica de retry usa backoff exponencial para não sobrecarregar os serviços
- Rate limiting é respeitado

### Cadeia de suprimentos

- As dependências são fixadas no `pyproject.toml`
- O Dependabot monitora dependências vulneráveis
- O `pip-audit` roda no CI
- A imagem Docker usa build multi-stage com tags de versão específicas

### Segurança de contêiner

- Usuário não-root na imagem Docker
- Suporte a sistema de arquivos somente leitura
- Todas as capabilities removidas
- Flag de no-new-privileges
- Healthcheck configurado
