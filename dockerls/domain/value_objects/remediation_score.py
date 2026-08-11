from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dockerls.domain.entities.scan_result import ScanResult


#: Faixas de `fixable / total` e a nota que cada uma vale. É uma escala
#: ordinal de cinco degraus, deliberadamente -- não uma porcentagem. A
#: proporção exata oscila a cada atualização de banco de vulnerabilidades, e
#: um número que muda de 41% para 39% sozinho sugere uma precisão que o dado
#: não tem. O degrau responde à pergunta que interessa: "dá para consertar a
#: maior parte disto?".
_BANDS: tuple[tuple[float, int], ...] = (
    (1.0, 100),
    (0.75, 80),
    (0.5, 60),
    (0.25, 40),
)
_LOWEST_BAND = 20


class RemediationScore:
    """Quão remediável é um scan, numa escala ordinal de 0 a 100.

    **Não é a porcentagem de vulnerabilidades corrigíveis.** É a razão
    `fixable / total` mapeada em cinco degraus:

    | fixable / total | nota |
    |-----------------|------|
    | 100%            | 100  |
    | >= 75%          |  80  |
    | >= 50%          |  60  |
    | >= 25%          |  40  |
    | < 25%           |  20  |
    | sem vulns       | 100  |

    Ou seja: 16 corrigíveis em 170 (9,4%) valem **20**, e isso está correto.
    Ler esse 20 como "20%" -- que era o que o terminal sugeria ao imprimir um
    `%` ao lado -- faz o número parecer errado por um fator de dois. Quem
    quiser a proporção crua a tem impressa ao lado, em `analyze`.
    """

    def __init__(self, scan: ScanResult):
        self._scan = scan
        self._value = self._calculate()

    @property
    def value(self) -> int:
        return self._value

    def _calculate(self) -> int:
        total = self._scan.total_count
        if total == 0:
            return 100

        ratio = self._scan.fixable_count / total
        for threshold, score in _BANDS:
            if ratio >= threshold:
                return score
        return _LOWEST_BAND
