from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dockerls.domain.entities.scan_result import ScanResult


class Tier(StrEnum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"


#: Do melhor para o pior. A ordem é explícita porque a trava de CRITICAL
#: precisa comparar tiers, e comparar letras alfabeticamente só funciona por
#: coincidência -- deixaria de funcionar no instante em que a escala mudar.
TIER_ORDER: tuple[Tier, ...] = (Tier.A, Tier.B, Tier.C, Tier.D, Tier.E, Tier.F)

#: Piso de score de cada faixa, do topo para a base. Cobre toda a faixa
#: 0-100: antes a escala parava em C, então um score 0.0 com 6 CRITICAL e 170
#: vulnerabilidades recebia exatamente o mesmo tier de uma imagem 36 pontos
#: melhor -- a nota deixava de discriminar justamente onde mais importava.
TIER_BANDS: tuple[tuple[float, Tier], ...] = (
    (90.0, Tier.A),
    (75.0, Tier.B),
    (60.0, Tier.C),
    (40.0, Tier.D),
    (20.0, Tier.E),
)
LOWEST_TIER = Tier.F

#: Melhor tier que uma imagem com CRITICAL sem correção disponível pode
#: alcançar. Um CRITICAL que nem dá para consertar não é compensável por
#: nenhum outro sinal: por mais alto que o score fique, a imagem não passa de
#: "exige revisão humana".
UNFIXABLE_CRITICAL_CEILING = Tier.C

#: Tiers que uma imagem precisa alcançar para ser considerada pronta para
#: produção, alinhado com `DockerfileAnalysis.is_production_ready`.
PRODUCTION_READY_TIERS = (Tier.A, Tier.B)


def tier_for_score(score: float) -> Tier:
    for floor, tier in TIER_BANDS:
        if score >= floor:
            return tier
    return LOWEST_TIER


class SecurityTier:
    """Traduz o score de segurança numa nota de A a F.

    A escala completa, documentada também no README:

    | Tier | Score   | Leitura                                    |
    |------|---------|--------------------------------------------|
    | A    | 90-100  | pronta para produção                       |
    | B    | 75-89   | pronta para produção                       |
    | C    | 60-74   | condicional: exige revisão humana           |
    | D    | 40-59   | não pronta para produção                    |
    | E    | 20-39   | não pronta para produção                    |
    | F    | 0-19    | não usar                                    |

    Sobre a trava: uma imagem com CRITICAL **sem correção disponível** nunca
    passa de C, por mais alto que o score tenha ficado. E uma base EOL nunca é
    production-ready, independentemente do tier -- ela vai parar de receber
    correções de segurança de qualquer forma.
    """

    ADVICE = {
        Tier.C: "conditional -- requires human review before production use",
        Tier.D: "not production ready",
        Tier.E: "not production ready",
        Tier.F: "not production ready -- do not deploy",
    }

    def __init__(self, scan: ScanResult, security_score: float, is_eol: bool = False):
        self._scan = scan
        self._score = security_score
        self._is_eol = is_eol
        self._tier = self._classify()

    @property
    def tier(self) -> Tier:
        return self._tier

    @property
    def unfixable_critical_count(self) -> int:
        return self._scan.critical_count - self._scan.fixable_critical_count

    @property
    def production_ready(self) -> bool:
        # An EOL base is never production-ready, regardless of its
        # vulnerability tier -- it will stop receiving security patches.
        if self._is_eol:
            return False
        return self._tier in PRODUCTION_READY_TIERS

    def _classify(self) -> Tier:
        tier = tier_for_score(self._score)
        if self.unfixable_critical_count > 0:
            tier = max(tier, UNFIXABLE_CRITICAL_CEILING, key=TIER_ORDER.index)
        return tier
