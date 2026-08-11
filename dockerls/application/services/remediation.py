"""Deriva um patch de Dockerfile a partir das vulnerabilidades encontradas.

O que esta ferramenta analisa é uma **imagem publicada**, não o Dockerfile de
quem a executa -- e não há como recuperar um do outro. Então o produto honesto
não é "o seu Dockerfile corrigido": é um patch que parte da imagem analisada e
aplica, em camadas, exatamente o que os achados justificam. Quem tem o
Dockerfile original copia as linhas; quem não tem constrói em cima.

Cada ação sai do dado, nunca de um palpite:

* pacotes de SO com correção disponível -> `apk upgrade` / `apt-get upgrade`,
  escolhido pela distro que o próprio scanner reportou no `Target`;
* pacotes de linguagem com correção -> upgrade do gerenciador correspondente;
* o npm embutido nas imagens Node -> as duas saídas reais (atualizar ou
  remover), porque `apk upgrade` não toca nele;
* achados sem correção -> nenhuma ação inventada, apenas o registro de que
  sobram e de que só trocar de base resolve.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dockerls.domain.entities.vulnerability import PackageOrigin

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from dockerls.application.dto.analysis import ImageAnalysis
    from dockerls.domain.entities.vulnerability import Vulnerability

# Marcadores de distro no `Target` do Trivy -> comando de upgrade. A ordem
# importa só para "ubuntu" não casar antes de "debian" em alvos que citam as
# duas; ambos usam apt, então o resultado é o mesmo de qualquer forma.
_OS_UPGRADE = (
    ("alpine", "apk", "apk upgrade --no-cache"),
    ("wolfi", "apk", "apk upgrade --no-cache"),
    ("chainguard", "apk", "apk upgrade --no-cache"),
    ("debian", "apt", "apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*"),
    ("ubuntu", "apt", "apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*"),
    ("redhat", "dnf", "dnf upgrade -y && dnf clean all"),
    ("centos", "dnf", "dnf upgrade -y && dnf clean all"),
    ("rocky", "dnf", "dnf upgrade -y && dnf clean all"),
    ("alma", "dnf", "dnf upgrade -y && dnf clean all"),
    ("amazon", "dnf", "dnf upgrade -y && dnf clean all"),
    ("photon", "tdnf", "tdnf upgrade -y && tdnf clean all"),
    ("suse", "zypper", "zypper update -y && zypper clean --all"),
)

# Ecossistema de linguagem -> como atualizar um pacote nomeado.
_LANG_UPGRADE = {
    "npm": "npm install -g {packages}",
    "yarn": "yarn global upgrade {packages}",
    "pip": "pip install --no-cache-dir --upgrade {packages}",
    "gem": "gem update {packages}",
    "composer": "composer global update {packages}",
}

_LANG_MARKERS = {
    "npm": ("npm", "node-pkg", "node_modules", "yarn"),
    "pip": ("pip", "python-pkg", "site-packages", "poetry"),
    "gem": ("gem", "gemspec", "ruby"),
    "composer": ("composer", "php"),
}

_NPM_BUNDLE_MARKERS = ("node_modules/npm", "/npm/")


@dataclass(frozen=True)
class RemediationAction:
    """Uma linha do patch, com o motivo que a justifica."""

    title: str
    dockerfile: str
    rationale: str
    addresses: tuple[str, ...] = ()
    #: Ações que não podem ser aplicadas junto com outra (atualizar o npm
    #: versus removê-lo). O chamador escolhe uma; ambas ficam no patch,
    #: com a alternativa comentada.
    alternative_to: str = ""

    @property
    def fixes(self) -> int:
        return len(self.addresses)


@dataclass
class RemediationPlan:
    image_reference: str
    actions: list[RemediationAction] = field(default_factory=list)
    #: CVEs que nenhuma ação deste plano resolve.
    unresolved: tuple[str, ...] = ()
    base_suggestion: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.actions and not self.base_suggestion

    @property
    def resolved_count(self) -> int:
        """Achados distintos cobertos por pelo menos uma ação."""
        covered: set[str] = set()
        for action in self.actions:
            covered.update(action.addresses)
        return len(covered)


def _ecosystem_of(vuln: Vulnerability) -> str | None:
    haystack = f"{vuln.package_type} {vuln.target}".lower()
    for ecosystem, markers in _LANG_MARKERS.items():
        if any(marker in haystack for marker in markers):
            return ecosystem
    return None


def _os_upgrade_for(vulns: Sequence[Vulnerability]) -> tuple[str, str] | None:
    """(nome do gerenciador, comando) para a distro que o scanner reportou."""
    haystack = " ".join(f"{v.package_type} {v.target}" for v in vulns).lower()
    for marker, manager, command in _OS_UPGRADE:
        if marker in haystack:
            return manager, command
    return None


def _is_bundled_npm(vuln: Vulnerability) -> bool:
    return vuln.origin is PackageOrigin.LANGUAGE and any(
        marker in vuln.target.lower() for marker in _NPM_BUNDLE_MARKERS
    )


def build_remediation_plan(analysis: ImageAnalysis) -> RemediationPlan:
    """Derive the actions the findings actually justify -- and nothing else."""
    vulns = list(analysis.scan.vulnerabilities)
    plan = RemediationPlan(image_reference=analysis.image.full_reference)
    if not vulns:
        return plan

    fixable = [v for v in vulns if v.is_fixable]
    handled: set[str] = set()

    # 1. O npm embutido vem primeiro: é o caso em que o upgrade genérico da
    #    linguagem não é a melhor resposta, e em que remover resolve tudo.
    bundled_npm = [v for v in vulns if _is_bundled_npm(v)]
    if bundled_npm:
        ids = tuple(v.cve_id for v in bundled_npm)
        plan.actions.append(
            RemediationAction(
                title="Update the bundled npm CLI",
                dockerfile="RUN npm install -g npm@latest",
                rationale=(
                    "These findings are in the npm CLI shipped inside the image, not in "
                    "OS packages -- apk/apt upgrade does not touch them."
                ),
                addresses=ids,
                alternative_to="remove-npm",
            )
        )
        plan.actions.append(
            RemediationAction(
                title="Remove the bundled npm CLI",
                dockerfile=(
                    "RUN rm -rf /usr/local/lib/node_modules/npm "
                    "/usr/local/bin/npm /usr/local/bin/npx"
                ),
                rationale=(
                    "If npm is not needed at runtime (multi-stage build shipping only "
                    "dist/), removing it clears every one of these findings outright."
                ),
                addresses=ids,
                alternative_to="update-npm",
            )
        )
        handled.update(ids)

    # 2. Pacotes de SO com correção publicada.
    os_fixable = [v for v in fixable if v.origin is PackageOrigin.OS]
    if os_fixable:
        upgrade = _os_upgrade_for(os_fixable)
        if upgrade is not None:
            manager, command = upgrade
            ids = tuple(v.cve_id for v in os_fixable)
            plan.actions.append(
                RemediationAction(
                    title=f"Upgrade OS packages ({manager})",
                    dockerfile=f"RUN {command}",
                    rationale=(
                        f"{len(ids)} OS-package finding(s) have a fixed version published upstream."
                    ),
                    addresses=ids,
                )
            )
            handled.update(ids)

    # 3. Pacotes de linguagem com correção, agrupados por ecossistema. O npm
    #    embutido já foi tratado acima e não se repete aqui.
    lang_fixable = [
        v for v in fixable if v.origin is PackageOrigin.LANGUAGE and not _is_bundled_npm(v)
    ]
    by_ecosystem: dict[str, list[Vulnerability]] = {}
    for vuln in lang_fixable:
        ecosystem = _ecosystem_of(vuln)
        if ecosystem in _LANG_UPGRADE:
            by_ecosystem.setdefault(str(ecosystem), []).append(vuln)

    for ecosystem, items in sorted(by_ecosystem.items()):
        # Pin ao alvo corrigido, não um upgrade cego: é o dado que o scanner
        # já entregou, e vale mais que "atualize tudo e torça".
        pinned = sorted({f"{v.package_name}@{v.fixed_version}" for v in items if v.package_name})
        if not pinned:
            continue
        template = _LANG_UPGRADE[ecosystem]
        if ecosystem in ("pip", "gem", "composer"):
            pinned = [p.replace("@", "==" if ecosystem == "pip" else ":") for p in pinned]
        ids = tuple(v.cve_id for v in items)
        plan.actions.append(
            RemediationAction(
                title=f"Upgrade {ecosystem} packages",
                dockerfile=f"RUN {template.format(packages=' '.join(pinned))}",
                rationale=f"{len(ids)} {ecosystem} finding(s) have a published fixed version.",
                addresses=ids,
            )
        )
        handled.update(ids)

    plan.unresolved = tuple(sorted({v.cve_id for v in vulns} - handled))

    # 4. Trocar de base só é sugerido quando sobra algo que as camadas acima
    #    não resolvem -- caso contrário seria conselho gratuito.
    if plan.unresolved and not (analysis.image.is_alpine or analysis.image.is_distroless):
        plan.base_suggestion = (
            f"{len(plan.unresolved)} finding(s) have no published fix. A minimal base "
            f"(alpine, distroless, or a hardened vendor image) removes the packages "
            f"they live in rather than patching them; `dockerls recommend "
            f"{analysis.image.name}` ranks the alternatives by measured vulnerabilities."
        )

    return plan


def render_dockerfile_patch(plan: RemediationPlan) -> str:
    """Render the plan as a Dockerfile that starts from the analysed image.

    Não é "o seu Dockerfile corrigido" -- esta ferramenta nunca viu o seu
    Dockerfile. É um patch aplicável: quem tem o original copia as camadas,
    quem não tem constrói a partir daqui.
    """
    lines = [
        "# Generated by dockerls --fix",
        f"# Base: {plan.image_reference}",
        "#",
        "# These layers are derived from the findings of a real scan of the image",
        "# above. dockerls analyses published images, not your Dockerfile, so this",
        "# is a patch to apply -- copy the RUN lines into your own build, or build",
        "# from here directly.",
    ]

    if plan.is_empty:
        lines += [
            "#",
            "# Nothing to remediate: no finding in this image has a published fix",
            "# that a layer could apply.",
            "",
            f"FROM {plan.image_reference}",
            "",
        ]
        return "\n".join(lines)

    lines += ["", f"FROM {plan.image_reference}", ""]

    chosen_alternatives: set[str] = set()
    for action in plan.actions:
        commented = bool(action.alternative_to) and action.alternative_to in chosen_alternatives
        if action.alternative_to:
            chosen_alternatives.add(_action_key(action))

        lines.append(f"# {action.title} -- fixes {action.fixes} finding(s)")
        for wrapped in _wrap_comment(action.rationale):
            lines.append(f"#   {wrapped}")
        if commented:
            lines.append("# Alternative to the layer above -- pick one, not both:")
            lines.append(f"# {action.dockerfile}")
        else:
            lines.append(action.dockerfile)
        lines.append("")

    if plan.unresolved:
        lines.append(f"# {len(plan.unresolved)} finding(s) remain with no published fix:")
        for cve in plan.unresolved[:20]:
            lines.append(f"#   {cve}")
        if len(plan.unresolved) > 20:
            lines.append(f"#   ... and {len(plan.unresolved) - 20} more")
        lines.append("")

    if plan.base_suggestion:
        for wrapped in _wrap_comment(plan.base_suggestion):
            lines.append(f"# {wrapped}")
        lines.append("")

    return "\n".join(lines)


def _action_key(action: RemediationAction) -> str:
    """A ação que a alternativa dela referencia por nome."""
    return "update-npm" if "install -g npm" in action.dockerfile else "remove-npm"


def _wrap_comment(text: str, width: int = 72) -> list[str]:
    words: Iterable[str] = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines
