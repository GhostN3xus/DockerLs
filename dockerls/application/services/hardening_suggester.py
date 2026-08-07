"""Turns validation findings into changes a developer can actually make.

A finding says "this Dockerfile runs as root". A suggestion says "add these
two lines, here, and this is what it buys you". The split matters: findings
gate a build, suggestions never do, and mixing them produces a tool that
either blocks on cosmetics or stays quiet about real improvements.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, NamedTuple

from dockerls.domain.entities.build_validation import CheckStatus
from dockerls.domain.entities.hardening_rule import HardeningRule, Priority
from dockerls.infrastructure.validators.dockerfile_security_rules import parse_key_values

if TYPE_CHECKING:
    from dockerls.domain.entities.build_validation import ValidationResult
    from dockerls.domain.entities.dockerfile_analysis import ParsedDockerfile


class BaseImageUpgrade(NamedTuple):
    suggested: str
    reason: str


# Hardened equivalents for the bases people actually start from. Keyed by
# the repository name so a tag of any version matches. These are
# recommendations, never automatic rewrites -- a Chainguard image has a
# different filesystem layout and swapping it in silently would break
# builds.
BASE_IMAGE_UPGRADES: dict[str, BaseImageUpgrade] = {
    "node": BaseImageUpgrade(
        "cgr.dev/chainguard/node:latest",
        "Chainguard's Wolfi-based Node images ship a fraction of the packages "
        "and are rebuilt daily against the current CVE feed",
    ),
    "python": BaseImageUpgrade(
        "cgr.dev/chainguard/python:latest",
        "Chainguard's Python images carry no shell or package manager in the "
        "runtime variant, removing most of the medium findings alpine still has",
    ),
    "golang": BaseImageUpgrade(
        "gcr.io/distroless/static-debian12:nonroot",
        "A statically linked Go binary needs no distribution at all; distroless "
        "static ships CA certificates and nothing else",
    ),
    "openjdk": BaseImageUpgrade(
        "gcr.io/distroless/java21-debian12:nonroot",
        "Distroless Java drops the shell and package manager from the runtime "
        "while keeping the JRE",
    ),
    "eclipse-temurin": BaseImageUpgrade(
        "gcr.io/distroless/java21-debian12:nonroot",
        "Distroless Java drops the shell and package manager from the runtime "
        "while keeping the JRE",
    ),
    "nginx": BaseImageUpgrade(
        "cgr.dev/chainguard/nginx:latest",
        "Chainguard's nginx runs unprivileged by default and tracks upstream patches within hours",
    ),
    "ubuntu": BaseImageUpgrade(
        "cgr.dev/chainguard/wolfi-base:latest",
        "A full Ubuntu userland is ~100 packages of attack surface for a "
        "process that usually needs none of it",
    ),
    "debian": BaseImageUpgrade(
        "gcr.io/distroless/base-debian12:nonroot",
        "Distroless keeps glibc and CA certificates and drops everything else, "
        "including the shell an attacker would need",
    ),
}

SBOM_LABEL = "org.opencontainers.image.description"
INSTALL_WITH_TOKEN = re.compile(
    r"\b(npm|yarn|pip|pip3|composer|bundle|go|cargo)\b.*\$\{?[A-Z_]*(TOKEN|SECRET|PASSWORD)"
)

_PRIORITY_ORDER = {Priority.HIGH: 0, Priority.MEDIUM: 1, Priority.LOW: 2}


class HardeningSuggester:
    def suggest(
        self,
        validation: ValidationResult,
        dockerfile: ParsedDockerfile | None = None,
    ) -> list[HardeningRule]:
        suggestions: list[HardeningRule] = []
        suggestions += self._from_findings(validation, dockerfile)
        if dockerfile is not None:
            suggestions += self._base_image_upgrades(dockerfile)
            suggestions += self._buildkit_secrets(dockerfile)
            suggestions += self._sbom_label(dockerfile)

        # Stable within a priority band: two runs over the same file must
        # produce the same report, or diffing two builds is meaningless.
        return sorted(suggestions, key=lambda r: (_PRIORITY_ORDER[r.priority], r.rule_id))

    def _from_findings(
        self,
        validation: ValidationResult,
        dockerfile: ParsedDockerfile | None,
    ) -> list[HardeningRule]:
        suggestions: list[HardeningRule] = []
        for check in validation.checks:
            if check.status not in (CheckStatus.FAIL, CheckStatus.WARN):
                continue
            suggestions.append(
                HardeningRule.from_severity(
                    check.severity,
                    rule_id=check.check,
                    title=check.title or check.check,
                    current=_source_line(dockerfile, check.line),
                    suggested=check.fix,
                    reason=check.message,
                    line=check.line,
                )
            )
        return suggestions

    def _base_image_upgrades(self, dockerfile: ParsedDockerfile) -> list[HardeningRule]:
        final = dockerfile.final_stage
        if final is None or final.is_scratch:
            return []
        repository = final.base_name.rsplit("/", 1)[-1].lower()
        upgrade = BASE_IMAGE_UPGRADES.get(repository)
        if upgrade is None:
            return []
        # Already on a hardened vendor: recommending it again is noise.
        if final.base_name.lower().startswith(("cgr.dev/", "gcr.io/distroless")):
            return []
        return [
            HardeningRule(
                rule_id="base_image_upgrade",
                title="A more hardened base image is available",
                priority=Priority.HIGH if not final.is_minimal_base else Priority.MEDIUM,
                current=final.base_image,
                suggested=upgrade.suggested,
                reason=upgrade.reason,
            )
        ]

    def _buildkit_secrets(self, dockerfile: ParsedDockerfile) -> list[HardeningRule]:
        """Flag package installs that consume a token through a build arg.

        This is the leak that survives every other rule: the ARG never
        appears in a final ENV, but it is recorded in the layer's command
        and `docker history` prints it back.
        """
        offenders = [
            run
            for run in dockerfile.instructions_of("RUN")
            if INSTALL_WITH_TOKEN.search(run.value) and "secret" not in run.flags.get("mount", "")
        ]
        if not offenders:
            return []
        return [
            HardeningRule(
                rule_id="buildkit_secrets",
                title="Use BuildKit secret mounts for registry tokens",
                priority=Priority.HIGH,
                current=offenders[0].raw.splitlines()[0][:120],
                suggested=(
                    "RUN --mount=type=secret,id=registry_token \\\n"
                    "    TOKEN=$(cat /run/secrets/registry_token) <install command>"
                ),
                reason=(
                    "A token passed as a build arg is recorded in the layer's "
                    "command and replayed by `docker history`"
                ),
                line=offenders[0].line,
            )
        ]

    def _sbom_label(self, dockerfile: ParsedDockerfile) -> list[HardeningRule]:
        labels = {
            key
            for instruction in dockerfile.instructions_of("LABEL")
            for key in _label_keys(instruction.value)
        }
        if any(label.startswith("sbom") or label == SBOM_LABEL for label in labels):
            return []
        return [
            HardeningRule(
                rule_id="sbom_declaration",
                title="Declare the SBOM alongside the image",
                priority=Priority.LOW,
                suggested='LABEL sbom.format="cyclonedx"\n'
                'LABEL sbom.location="/usr/share/sbom.json"',
                reason=(
                    "`dockerls build --scan` already generates a CycloneDX SBOM; "
                    "labelling it lets downstream tooling find it without guessing"
                ),
            )
        ]


def _label_keys(value: str) -> list[str]:
    """Lower-cased keys of a LABEL instruction, in either supported form."""
    return [key.lower() for key, _ in parse_key_values(value)]


def _source_line(dockerfile: ParsedDockerfile | None, line: int) -> str:
    if dockerfile is None or line <= 0 or line > len(dockerfile.lines):
        return ""
    return dockerfile.lines[line - 1].strip()
