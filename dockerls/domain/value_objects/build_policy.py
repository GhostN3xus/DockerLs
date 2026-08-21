"""A política da organização, escrita uma vez e conferida em todo build.

`--fail-on critical` é um portão, mas é um portão que mora na linha de comando
-- e uma regra que mora na linha de comando é uma regra que cada pipeline
reescreve à mão. Bastava um `--fail-on high` esquecido num repositório para
que a política da organização deixasse de valer ali, sem que nada acusasse.

Este módulo é a política como dado: um `.dockerls-policy.yaml` versionado junto
do código, conferido contra o que foi **medido** neste build. A parte aqui é
pura -- recebe os fatos e devolve as violações -- para que cada regra seja
testável contra o número exato que a produziu.

Três princípios moldam o que existe e o que não existe aqui:

* **Só entra o que é mensurável.** Não há regra de "não use pacotes inseguros"
  ou "mantenha a imagem pequena": não há como decidir isso a partir de um
  build, e uma regra que não pode ser avaliada é uma regra que reprova por
  engano ou aprova por omissão. As duas corroem a confiança no portão.
* **Não medir nunca aprova.** Toda regra que dependa de uma medição que não
  aconteceu vira violação, não silêncio. É o mesmo princípio que impede uma
  imagem não escaneada de ser apresentada como segura.
* **A política nunca afrouxa o que a linha de comando apertou.** Quando as
  duas discordam, vale a mais estrita. Um arquivo no repositório não pode
  desligar um portão que o pipeline pediu -- senão bastaria commitar um YAML
  para publicar o que não passaria.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from dockerls.domain.value_objects.tristate import Tristate

#: Severidades ordenadas da mais grave para a menos. A ordem é o que permite
#: dizer "critical implica também high" sem repetir a lista em cada regra.
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "unknown")


class PolicyRule(StrEnum):
    """Cada regra que a política pode exigir, nomeada para o relatório."""

    FAIL_ON = "fail_on"
    MAX_VULNERABILITIES = "max_vulnerabilities"
    REQUIRE_SCAN = "require_scan"
    REQUIRE_PINNED_BASES = "require_pinned_bases"
    REQUIRE_NONROOT = "require_nonroot"
    REQUIRED_LABELS = "required_labels"
    ALLOWED_BASE_REGISTRIES = "allowed_base_registries"
    REQUIRE_PROVENANCE = "require_provenance"


@dataclass(frozen=True)
class BaseFact:
    """Uma base declarada, reduzida ao que a política consegue avaliar."""

    reference: str
    registry: str
    pinned: bool


@dataclass(frozen=True)
class PolicyFacts:
    """O que este build mediu. Tudo que a política tem para trabalhar."""

    #: Se um scanner chegou a rodar. `False` não é "zero vulnerabilidades".
    scan_ran: bool = False
    #: Contagem por severidade, do scan que rodou.
    severity_counts: dict[str, int] = field(default_factory=dict)
    bases: tuple[BaseFact, ...] = ()
    labels: dict[str, str] = field(default_factory=dict)
    #: Se a imagem roda sem privilégio. `UNKNOWN` quando o Dockerfile não
    #: permitiu decidir -- e a política trata isso como violação, não como sim.
    nonroot: Tristate = Tristate.UNKNOWN
    #: `VERIFIED`, `INCOMPLETE`, `INPUT_CHANGED`, ou "" quando não houve
    #: registro de procedência neste build.
    provenance_status: str = ""


@dataclass(frozen=True)
class PolicyViolation:
    """Uma regra que este build não cumpriu, e por quê."""

    rule: PolicyRule
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"rule": str(self.rule), "message": self.message}


@dataclass(frozen=True)
class BuildPolicy:
    """As exigências declaradas em `.dockerls-policy.yaml`."""

    #: Severidade a partir da qual o build reprova. Vazio deixa a decisão com
    #: a linha de comando.
    fail_on: str = ""
    #: Teto por severidade (`{"high": 5}`). Um teto de zero é diferente de
    #: `fail_on`: permite tolerar 3 HIGH e nenhum CRITICAL no mesmo arquivo.
    max_vulnerabilities: dict[str, int] = field(default_factory=dict)
    require_scan: bool = False
    require_pinned_bases: bool = False
    require_nonroot: bool = False
    required_labels: tuple[str, ...] = ()
    #: Registries de onde as bases podem vir. Vazio não restringe; declarado,
    #: restringe **todas** as bases, inclusive as de estágios intermediários.
    allowed_base_registries: tuple[str, ...] = ()
    require_provenance: bool = False

    @property
    def is_empty(self) -> bool:
        """Uma política que não exige nada. Vale saber: um arquivo presente e
        vazio quase sempre significa um erro de digitação nas chaves."""
        return not (
            self.fail_on
            or self.max_vulnerabilities
            or self.require_scan
            or self.require_pinned_bases
            or self.require_nonroot
            or self.required_labels
            or self.allowed_base_registries
            or self.require_provenance
        )

    def effective_fail_on(self, requested: str) -> str:
        """O limiar que vale, entre o da política e o da linha de comando.

        Vence o mais estrito. Um arquivo no repositório não pode desligar um
        portão que o pipeline pediu -- senão bastaria commitar um YAML para
        publicar o que não passaria.
        """
        candidates = [s for s in (self.fail_on, requested) if s in SEVERITY_ORDER]
        if not candidates:
            return requested or self.fail_on
        return min(candidates, key=SEVERITY_ORDER.index)

    def to_dict(self) -> dict[str, object]:
        return {
            "fail_on": self.fail_on,
            "max_vulnerabilities": dict(self.max_vulnerabilities),
            "require_scan": self.require_scan,
            "require_pinned_bases": self.require_pinned_bases,
            "require_nonroot": self.require_nonroot,
            "required_labels": list(self.required_labels),
            "allowed_base_registries": list(self.allowed_base_registries),
            "require_provenance": self.require_provenance,
        }


def evaluate(policy: BuildPolicy, facts: PolicyFacts) -> list[PolicyViolation]:
    """As regras que este build não cumpriu, na ordem em que foram declaradas.

    Uma lista vazia significa "nenhuma regra foi violada", e não "está tudo
    bem": uma política vazia não viola nada e também não garante nada. Quem
    consome precisa olhar a política junto do resultado, e é por isso que
    `is_empty` existe.
    """
    violations: list[PolicyViolation] = []

    _check_scan(policy, facts, violations)
    _check_ceilings(policy, facts, violations)
    _check_bases(policy, facts, violations)
    _check_nonroot(policy, facts, violations)
    _check_labels(policy, facts, violations)
    _check_provenance(policy, facts, violations)
    return violations


def _check_scan(policy: BuildPolicy, facts: PolicyFacts, violations: list[PolicyViolation]) -> None:
    if policy.require_scan and not facts.scan_ran:
        violations.append(
            PolicyViolation(
                rule=PolicyRule.REQUIRE_SCAN,
                message=(
                    "a política exige scan e nenhum scanner rodou: uma imagem que não "
                    "pôde ser medida não é uma imagem sem vulnerabilidades"
                ),
            )
        )


def _check_ceilings(
    policy: BuildPolicy, facts: PolicyFacts, violations: list[PolicyViolation]
) -> None:
    if not policy.max_vulnerabilities:
        return
    if not facts.scan_ran:
        # Sem scan não há contagem, e "contagem ausente" não é "contagem
        # dentro do teto". Aprovar aqui esvaziaria toda regra de teto numa
        # máquina sem scanner.
        violations.append(
            PolicyViolation(
                rule=PolicyRule.MAX_VULNERABILITIES,
                message=(
                    "a política declara tetos por severidade e nenhum scanner rodou: "
                    "não há contagem para conferir contra eles"
                ),
            )
        )
        return
    for severity in SEVERITY_ORDER:
        if severity not in policy.max_vulnerabilities:
            continue
        limit = policy.max_vulnerabilities[severity]
        found = facts.severity_counts.get(severity, 0)
        if found > limit:
            violations.append(
                PolicyViolation(
                    rule=PolicyRule.MAX_VULNERABILITIES,
                    message=(
                        f"{found} vulnerabilidade(s) {severity.upper()} contra um teto "
                        f"de {limit} na política"
                    ),
                )
            )


def _check_bases(
    policy: BuildPolicy, facts: PolicyFacts, violations: list[PolicyViolation]
) -> None:
    if policy.require_pinned_bases:
        if not facts.bases:
            violations.append(
                PolicyViolation(
                    rule=PolicyRule.REQUIRE_PINNED_BASES,
                    message=(
                        "a política exige bases fixadas por digest e nenhuma base pôde "
                        "ser lida do Dockerfile"
                    ),
                )
            )
        for base in facts.bases:
            if not base.pinned:
                violations.append(
                    PolicyViolation(
                        rule=PolicyRule.REQUIRE_PINNED_BASES,
                        message=(
                            f"{base.reference} não está fixada por digest: o que foi "
                            "testado e o que vai para produção podem ser bytes "
                            "diferentes sem nenhuma mudança sua"
                        ),
                    )
                )

    if not policy.allowed_base_registries:
        return
    permitidos = {r.lower() for r in policy.allowed_base_registries}
    for base in facts.bases:
        # Uma base sem host explícito vem do Docker Hub; tratá-la como "sem
        # registry" faria a regra ignorar exatamente o caso mais comum.
        registry = (base.registry or "docker.io").lower()
        if registry not in permitidos:
            violations.append(
                PolicyViolation(
                    rule=PolicyRule.ALLOWED_BASE_REGISTRIES,
                    message=(
                        f"{base.reference} vem de {registry}, que não está entre os "
                        f"registries permitidos ({', '.join(sorted(permitidos))})"
                    ),
                )
            )


def _check_nonroot(
    policy: BuildPolicy, facts: PolicyFacts, violations: list[PolicyViolation]
) -> None:
    if not policy.require_nonroot or facts.nonroot.is_true:
        return
    motivo = (
        "a imagem roda como root"
        if facts.nonroot.is_false
        else "não foi possível determinar com que usuário a imagem roda, e não "
        "determinar não é o mesmo que estar em ordem"
    )
    violations.append(
        PolicyViolation(
            rule=PolicyRule.REQUIRE_NONROOT,
            message=f"a política exige execução sem privilégio: {motivo}",
        )
    )


def _check_labels(
    policy: BuildPolicy, facts: PolicyFacts, violations: list[PolicyViolation]
) -> None:
    for label in policy.required_labels:
        if not facts.labels.get(label, "").strip():
            violations.append(
                PolicyViolation(
                    rule=PolicyRule.REQUIRED_LABELS,
                    message=(
                        f"rótulo obrigatório ausente ou vazio: {label} -- sem ele "
                        "ninguém sabe a quem recorrer quando esta imagem aparecer num "
                        "alerta às três da manhã"
                    ),
                )
            )


def _check_provenance(
    policy: BuildPolicy, facts: PolicyFacts, violations: list[PolicyViolation]
) -> None:
    if not policy.require_provenance:
        return
    if facts.provenance_status == "VERIFIED":
        return
    detalhe = facts.provenance_status or "nenhum registro foi produzido"
    violations.append(
        PolicyViolation(
            rule=PolicyRule.REQUIRE_PROVENANCE,
            message=(f"a política exige procedência verificada, e o registro está: {detalhe}"),
        )
    )
