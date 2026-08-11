"""Invariantes de arquitetura, verificados no AST em vez de na revisão.

O invariante 1 é o que sustenta todos os outros: `domain/` é puro. No dia em
que uma entidade de domínio importar `httpx`, a regra deixa de ser testável
sem rede e o motor de score deixa de ser reproduzível. Isso não sobrevive a
"lembrar de não fazer" -- vira teste.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

PACKAGE = pathlib.Path(__file__).resolve().parents[2] / "dockerls"
DOMAIN = PACKAGE / "domain"
APPLICATION = PACKAGE / "application"

#: O que uma camada pura não pode alcançar, direta ou indiretamente.
_IO_MODULES = {
    "httpx",
    "subprocess",
    "sqlalchemy",
    "typer",
    "rich",
    "asyncio",
    "socket",
    "requests",
    "urllib",
    "keyring",
}

#: Pacotes do próprio projeto que o domínio não pode importar.
_FORBIDDEN_PACKAGES = ("dockerls.infrastructure", "dockerls.integrations", "dockerls.cli")


def _imports_of(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def _python_files(root: pathlib.Path) -> list[pathlib.Path]:
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


DOMAIN_FILES = _python_files(DOMAIN)


class TestDomainIsPure:
    def test_there_are_domain_files_to_check(self):
        """Um teste de arquitetura que não vê arquivo nenhum passa por
        engano -- e passaria para sempre."""
        assert DOMAIN_FILES

    @pytest.mark.parametrize("path", DOMAIN_FILES, ids=lambda p: p.name)
    def test_no_domain_module_imports_infrastructure(self, path):
        offenders = [
            name
            for name in _imports_of(path)
            if any(name.startswith(package) for package in _FORBIDDEN_PACKAGES)
        ]

        assert offenders == [], (
            f"{path.relative_to(PACKAGE)} imports {offenders} -- domain must not "
            f"reach into an outer layer"
        )

    @pytest.mark.parametrize("path", DOMAIN_FILES, ids=lambda p: p.name)
    def test_no_domain_module_imports_io(self, path):
        offenders = [name for name in _imports_of(path) if name.split(".")[0] in _IO_MODULES]

        assert offenders == [], (
            f"{path.relative_to(PACKAGE)} imports {offenders} -- domain must stay "
            f"pure so its rules are testable without network, disk or a daemon"
        )

    def test_domain_is_importable_without_touching_the_outer_layers(self):
        """Importar o domínio inteiro não pode arrastar I/O junto."""
        import importlib

        for path in DOMAIN_FILES:
            if path.name == "__init__.py":
                continue
            module = ".".join(path.relative_to(PACKAGE.parent).with_suffix("").parts)
            importlib.import_module(module)


class TestApplicationDoesNotReachTheCli:
    """A aplicação orquestra; quem desenha tabela é a camada de cima. Um caso
    de uso que importa `rich` já decidiu como o resultado é exibido."""

    @pytest.mark.parametrize("path", _python_files(APPLICATION), ids=lambda p: p.name)
    def test_no_use_case_imports_the_cli(self, path):
        offenders = [n for n in _imports_of(path) if n.startswith("dockerls.cli")]

        assert offenders == [], f"{path.relative_to(PACKAGE)} imports {offenders}"


class TestNoShellTrue:
    """Invariante 2: nenhum subprocess com `shell=True` em lugar nenhum."""

    @pytest.mark.parametrize("path", _python_files(PACKAGE), ids=lambda p: p.name)
    def test_no_module_uses_shell_true(self, path):
        text = path.read_text(encoding="utf-8")

        assert "shell=True" not in text, f"{path.relative_to(PACKAGE)} runs a shell"
