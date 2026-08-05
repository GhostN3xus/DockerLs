# Contributing to DockerLs

## Getting started

1. Fork the repository
2. Clone your fork
3. Create a feature branch: `git checkout -b feature/my-feature`
4. Install dev dependencies: `make dev`
5. Make your changes
6. Run checks: `make audit`
7. Commit and push
8. Open a pull request

## Development setup

```bash
git clone https://github.com/GhostN3xus/DockerLs.git
cd DockerLs
python -m venv .venv
source .venv/bin/activate
make dev
```

## Code standards

- Follow existing code style
- Run `make lint` before committing
- Run `make test` to verify all tests pass
- Add tests for new features
- Keep functions focused and small

## Pull request process

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure CI passes
4. One approval required for merge

## Reporting issues

Use GitHub Issues. Include:

- DockerLs version
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
