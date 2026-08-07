# Contribuindo com o DockerLs

## Primeiros passos

1. Faça um fork do repositório
2. Clone o seu fork
3. Crie um branch de funcionalidade: `git checkout -b feature/minha-funcionalidade`
4. Instale as dependências de desenvolvimento: `make dev`
5. Faça as suas alterações
6. Rode as verificações: `make audit`
7. Faça commit e push
8. Abra um pull request

## Preparando o ambiente de desenvolvimento

```bash
git clone https://github.com/GhostN3xus/DockerLs.git
cd DockerLs
python -m venv .venv
source .venv/bin/activate
make dev
```

## Padrões de código

- Siga o estilo de código já existente
- Rode `make lint` antes de fazer commit
- Rode `make test` para verificar que todos os testes passam
- Adicione testes para funcionalidades novas
- Mantenha as funções pequenas e com um único propósito

## Processo de pull request

1. Atualize a documentação, se necessário
2. Adicione testes para o comportamento novo
3. Garanta que o CI está passando
4. É necessária uma aprovação para o merge

## Reportando problemas

Use as GitHub Issues. Inclua:

- Versão do DockerLs
- Versão do Python
- Sistema operacional
- Passos para reproduzir
- Comportamento esperado versus comportamento observado
