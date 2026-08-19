"""Digest determinístico da entrada do build.

Determinístico é o requisito, não um detalhe: o mesmo conteúdo tem de dar o
mesmo hash em qualquer máquina e em qualquer ordem de sistema de arquivos, ou
comparar dois builds não significa nada.
"""

from __future__ import annotations

import pytest

from dockerls.infrastructure.hashing import (
    ContextTooLargeError,
    hash_context,
    hash_file,
)


def _write(root, relative: str, content: str = "x"):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


class TestFileDigest:
    def test_same_content_same_digest(self, tmp_path):
        a, b = _write(tmp_path, "a.txt", "conteúdo"), _write(tmp_path, "b.txt", "conteúdo")
        assert hash_file(a) == hash_file(b)

    def test_digest_is_prefixed(self, tmp_path):
        assert hash_file(_write(tmp_path, "a.txt")).startswith("sha256:")

    def test_one_byte_changes_the_digest(self, tmp_path):
        path = _write(tmp_path, "a.txt", "conteúdo")
        before = hash_file(path)
        path.write_text("conteúdoo")
        assert hash_file(path) != before


class TestContextDigest:
    def test_identical_trees_agree(self, tmp_path):
        for root in ("um", "dois"):
            _write(tmp_path / root, "app/main.py", "print(1)")
            _write(tmp_path / root, "Dockerfile", "FROM x")
        first, count = hash_context(tmp_path / "um")
        second, _ = hash_context(tmp_path / "dois")
        assert first == second
        assert count == 2

    def test_renaming_a_file_changes_the_context(self, tmp_path):
        _write(tmp_path, "a.py", "mesmo conteúdo")
        before, _ = hash_context(tmp_path)
        (tmp_path / "a.py").rename(tmp_path / "b.py")
        after, _ = hash_context(tmp_path)
        # O nome entra no digest: renomear muda o contexto tanto quanto editar.
        assert after != before

    def test_dockerignore_entries_are_excluded(self, tmp_path):
        _write(tmp_path, "app.py", "código")
        _write(tmp_path, "Dockerfile", "FROM x")
        _write(tmp_path, ".dockerignore", ".git\n*.log\n")
        baseline, count = hash_context(tmp_path)

        _write(tmp_path, ".git/HEAD", "ref: refs/heads/main")
        _write(tmp_path, "debug.log", "ruído")
        after, count_after = hash_context(tmp_path)

        # Um digest que mudasse com o que o daemon nem recebe dispararia sem
        # motivo -- e um controle que dispara à toa é um controle desligado.
        assert after == baseline
        assert count_after == count

    def test_negations_do_not_become_exclusions(self, tmp_path):
        _write(tmp_path, ".env.example", "CHAVE=")
        _write(tmp_path, ".dockerignore", ".env\n.env.*\n!.env.example\n")
        _, count = hash_context(tmp_path)
        assert count >= 1

    def test_an_oversized_context_is_refused_not_truncated(self, tmp_path, monkeypatch):
        monkeypatch.setattr("dockerls.infrastructure.hashing.MAX_CONTEXT_FILES", 3)
        for i in range(5):
            _write(tmp_path, f"f{i}.txt")
        with pytest.raises(ContextTooLargeError, match="dockerignore"):
            hash_context(tmp_path)
