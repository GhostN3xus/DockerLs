"""Resolução de executáveis externos.

Chamar `docker` ou `trivy` pelo nome puro entrega a escolha do binário ao
`$PATH` — o mesmo PATH hijacking que esta ferramenta reporta nas imagens dos
outros, e num scanner de segurança é o veredito que fica sequestrado.
"""

from __future__ import annotations

import pytest

from dockerls.utils.executables import ExecutableNotFoundError, resolve_executable


class TestResolveExecutable:
    def test_returns_the_absolute_path(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}")
        assert resolve_executable("docker") == "/usr/bin/docker"

    def test_missing_tool_raises_naming_it(self, monkeypatch):
        """A mensagem precisa dizer qual ferramenta falta.

        "command not found" sem nome manda o usuário caçar qual das três é.
        """
        monkeypatch.setattr("shutil.which", lambda name: None)
        with pytest.raises(ExecutableNotFoundError) as exc:
            resolve_executable("trivy")

        assert exc.value.name == "trivy"
        assert "trivy" in str(exc.value)
        assert "PATH" in str(exc.value)
