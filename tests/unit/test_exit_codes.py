"""Testes para `dockerls/exit_codes.py`.

O contrato de saída (`build --validate-only` e `analyze-dockerfile`) depende
destes três valores serem estáveis e distintos: um pipeline de CI decide se
falha ou não olhando exclusivamente para o exit code do processo.
"""

from __future__ import annotations

from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY


class TestExitCodeValues:
    def test_ok_is_zero(self):
        assert EXIT_OK == 0

    def test_error_is_one(self):
        assert EXIT_ERROR == 1

    def test_policy_is_two(self):
        assert EXIT_POLICY == 2

    def test_all_three_codes_are_distinct(self):
        assert len({EXIT_OK, EXIT_ERROR, EXIT_POLICY}) == 3

    def test_all_codes_are_valid_process_exit_codes(self):
        """POSIX exit codes are unsigned bytes; anything outside 0-255 would
        get silently truncated by the shell, making the contract lie."""
        for code in (EXIT_OK, EXIT_ERROR, EXIT_POLICY):
            assert isinstance(code, int)
            assert 0 <= code <= 255
