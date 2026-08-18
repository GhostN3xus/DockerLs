"""Hardening score: how well-configured an image is, independently of its CVEs.

Two images with identical vulnerability counts are not equally safe. One may
run as root with a shell, a package manager and a compiler in it; the other
may run as an unprivileged account with none of that. Nothing in a CVE count
expresses the difference, which is why hardening is a separate dimension
here rather than a term folded into the security score.

**Scoring over determined facts only.** The obvious design -- fixed weights
summed into a fixed maximum -- fails on the data actually available. Most
facts about most images cannot be determined without unpacking a filesystem,
so a fixed denominator would give a genuinely excellent image a score in the
thirties purely because nobody could inspect it, and that number would be
read as a hardening verdict. Instead the denominator is the weight of the
facts that *were* determined, and `coverage` reports how much of the model
that represents. A score of 100 at 30% coverage says "everything we could
check was good, and we could check less than a third of it" -- which is the
truth, and is what `Confidence` and the renderers surface next to it.

**Hardening never masks vulnerabilities.** This score is deliberately not an
input to `SecurityScore`. It is reported beside it, and the verdict layer
enforces the rule that no hardening result can lift an image carrying an
unfixable CRITICAL into "production ready". A perfectly configured image
full of exploitable CVEs is a perfectly configured vulnerable image.

Every weight below is a constant, documented in place, and covered by tests
that pin the arithmetic. Nothing here is tuned per-image or per-vendor.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from dockerls.domain.value_objects.tristate import Tristate

if TYPE_CHECKING:
    from dockerls.domain.entities.image_facts import HardeningFacts

#: Weight of each hardening property, and the direction that earns credit.
#: The privilege facts dominate because privilege is what turns a bug into a
#: breach: a shell in an image that runs as an unprivileged account with no
#: capabilities is a much smaller problem than root with no shell.
NON_ROOT_WEIGHT = 25.0
NO_SHELL_WEIGHT = 15.0
NO_PACKAGE_MANAGER_WEIGHT = 12.0
NO_DEBUG_TOOLS_WEIGHT = 8.0
NO_SETUID_WEIGHT = 10.0
NO_PRIVILEGED_PORTS_WEIGHT = 8.0
MINIMAL_PACKAGES_WEIGHT = 12.0
EXPLICIT_ENTRYPOINT_WEIGHT = 5.0
HEALTHCHECK_WEIGHT = 5.0

#: Total weight of the model, used to express coverage. Not a denominator
#: for the score itself -- see the module docstring.
TOTAL_WEIGHT = (
    NON_ROOT_WEIGHT
    + NO_SHELL_WEIGHT
    + NO_PACKAGE_MANAGER_WEIGHT
    + NO_DEBUG_TOOLS_WEIGHT
    + NO_SETUID_WEIGHT
    + NO_PRIVILEGED_PORTS_WEIGHT
    + MINIMAL_PACKAGES_WEIGHT
    + EXPLICIT_ENTRYPOINT_WEIGHT
    + HEALTHCHECK_WEIGHT
)

#: A package set at or below this is treated as minimal. Chosen from the
#: catalogue data: hardened runtime definitions install 10-40 packages,
#: while a general-purpose base lands in the hundreds.
MINIMAL_PACKAGE_COUNT = 50

#: Below this share of the model, the score is not reported as a number.
#: Two determined facts cannot characterise an image's hardening, and a
#: confident-looking number computed from them would be worse than no
#: number at all.
MIN_REPORTABLE_COVERAGE = 0.25


class HardeningFactor(NamedTuple):
    """One scored property, kept so the score can explain itself."""

    name: str
    weight: float
    #: Credit earned, 0.0 to `weight`.
    earned: float
    #: False when the underlying fact was not determined; such a factor
    #: contributes to neither the numerator nor the denominator.
    determined: bool
    detail: str = ""


class HardeningScore:
    """Deterministic 0-100 hardening rating over the facts that are known."""

    def __init__(self, facts: HardeningFacts):
        self._facts = facts
        self._factors = _score_factors(facts)
        determined = [f for f in self._factors if f.determined]
        self._available = sum(f.weight for f in determined)
        self._earned = sum(f.earned for f in determined)
        self._value = (
            round(100.0 * self._earned / self._available, 1) if self._available > 0 else 0.0
        )

    @property
    def value(self) -> float:
        """0-100 over the determined facts. Meaningless below `MIN_REPORTABLE_COVERAGE`."""
        return self._value

    @property
    def coverage(self) -> float:
        """Share of the hardening model that could be determined, 0.0-1.0."""
        return round(self._available / TOTAL_WEIGHT, 3)

    @property
    def is_reportable(self) -> bool:
        """Whether enough was determined for the number to mean anything."""
        return self.coverage >= MIN_REPORTABLE_COVERAGE

    @property
    def strengths(self) -> list[str]:
        """Determined properties that earned full credit, for the "why" text."""
        return [f.detail or f.name for f in self._factors if f.determined and f.earned >= f.weight]

    @property
    def weaknesses(self) -> list[str]:
        """Determined properties that earned nothing -- real, named findings."""
        return [f.detail or f.name for f in self._factors if f.determined and f.earned <= 0.0]

    @property
    def undetermined(self) -> list[str]:
        """Properties nothing could establish, stated rather than hidden."""
        return [f.name for f in self._factors if not f.determined]


def _score_factors(facts: HardeningFacts) -> list[HardeningFactor]:
    """Evaluate every factor, marking the ones nothing determined.

    Written as one flat list rather than a chain of conditionals so the
    model is readable end to end: each line is a property, its weight, and
    the fact that decides it.
    """
    return [
        _from_tristate(
            "non-root",
            NON_ROOT_WEIGHT,
            facts.runs_as_non_root,
            good=f"runs as {facts.user or 'a non-root account'}",
            bad="runs as root by default",
        ),
        _from_tristate(
            "no-shell",
            NO_SHELL_WEIGHT,
            _negate(facts.has_shell),
            good="no shell present",
            bad="ships an interactive shell",
        ),
        _from_tristate(
            "no-package-manager",
            NO_PACKAGE_MANAGER_WEIGHT,
            _negate(facts.has_package_manager),
            good="no package manager present",
            bad="ships a package manager",
        ),
        _from_tristate(
            "no-debug-tools",
            NO_DEBUG_TOOLS_WEIGHT,
            _negate(facts.has_debug_tools),
            good="no compilers or network utilities",
            bad="ships compilers or network utilities",
        ),
        _from_tristate(
            "no-setuid",
            NO_SETUID_WEIGHT,
            _negate(facts.has_setuid),
            good="no SUID/SGID binaries",
            bad="contains SUID/SGID binaries",
        ),
        _privileged_ports(facts),
        _minimal_packages(facts),
        _entrypoint(facts),
        _from_tristate(
            "healthcheck",
            HEALTHCHECK_WEIGHT,
            facts.has_healthcheck,
            good="declares a healthcheck",
            bad="declares no healthcheck",
        ),
    ]


def _negate(state: Tristate) -> Tristate:
    """Invert a fact, preserving UNKNOWN.

    `not has_shell` on a bool would turn "nobody looked" into "no shell",
    which is the exact substitution this module exists to prevent.
    """
    if state is Tristate.UNKNOWN:
        return Tristate.UNKNOWN
    return Tristate.FALSE if state.is_true else Tristate.TRUE


def _from_tristate(
    name: str, weight: float, state: Tristate, *, good: str, bad: str
) -> HardeningFactor:
    if not state.is_known:
        return HardeningFactor(name, weight, 0.0, determined=False)
    earned = weight if state.is_true else 0.0
    return HardeningFactor(
        name, weight, earned, determined=True, detail=good if state.is_true else bad
    )


def _privileged_ports(facts: HardeningFacts) -> HardeningFactor:
    """Credit for declaring no port that implies elevated privileges.

    Determined only when the OCI config was actually read: an image whose
    config was never fetched has an empty port list because nothing looked,
    not because it declares none.
    """
    name = "no-privileged-ports"
    if not facts.ports_known:
        return HardeningFactor(name, NO_PRIVILEGED_PORTS_WEIGHT, 0.0, determined=False)
    privileged = facts.privileged_ports
    if privileged:
        detail = f"exposes privileged port(s) {', '.join(str(p) for p in sorted(privileged))}"
        return HardeningFactor(
            name, NO_PRIVILEGED_PORTS_WEIGHT, 0.0, determined=True, detail=detail
        )
    return HardeningFactor(
        name,
        NO_PRIVILEGED_PORTS_WEIGHT,
        NO_PRIVILEGED_PORTS_WEIGHT,
        determined=True,
        detail="exposes no privileged ports",
    )


def _minimal_packages(facts: HardeningFacts) -> HardeningFactor:
    """Credit for a small package set, scaled rather than a cliff edge.

    A step function at exactly 50 packages would rank a 50-package image
    far above a 51-package one, which is not a real difference. Credit
    tapers from full at `MINIMAL_PACKAGE_COUNT` to zero at four times that.
    """
    name = "minimal-packages"
    count = facts.package_count
    if count is None:
        return HardeningFactor(name, MINIMAL_PACKAGES_WEIGHT, 0.0, determined=False)
    ceiling = MINIMAL_PACKAGE_COUNT * 4
    if count <= MINIMAL_PACKAGE_COUNT:
        earned = MINIMAL_PACKAGES_WEIGHT
    elif count >= ceiling:
        earned = 0.0
    else:
        span = ceiling - MINIMAL_PACKAGE_COUNT
        earned = MINIMAL_PACKAGES_WEIGHT * (ceiling - count) / span
    return HardeningFactor(
        name,
        MINIMAL_PACKAGES_WEIGHT,
        round(earned, 3),
        determined=True,
        detail=f"{count} packages",
    )


def _entrypoint(facts: HardeningFacts) -> HardeningFactor:
    """Credit for declaring an explicit entrypoint.

    An image with a fixed entrypoint constrains what running it does; one
    whose entrypoint is a shell does the opposite, and is scored as such.
    """
    name = "explicit-entrypoint"
    if not facts.config_verified:
        return HardeningFactor(name, EXPLICIT_ENTRYPOINT_WEIGHT, 0.0, determined=False)
    entry = facts.entrypoint or facts.cmd
    if not entry:
        return HardeningFactor(
            name, EXPLICIT_ENTRYPOINT_WEIGHT, 0.0, determined=True, detail="declares no entrypoint"
        )
    if _is_shell_entrypoint(entry):
        return HardeningFactor(
            name,
            EXPLICIT_ENTRYPOINT_WEIGHT,
            0.0,
            determined=True,
            detail=f"entrypoint is a shell ({entry[0]})",
        )
    return HardeningFactor(
        name,
        EXPLICIT_ENTRYPOINT_WEIGHT,
        EXPLICIT_ENTRYPOINT_WEIGHT,
        determined=True,
        detail=f"entrypoint {' '.join(entry[:2])}",
    )


_SHELL_BASENAMES = frozenset({"sh", "bash", "ash", "dash", "zsh", "ksh", "busybox"})


def _is_shell_entrypoint(entry: list[str]) -> bool:
    head = entry[0].strip() if entry else ""
    return head.rsplit("/", 1)[-1] in _SHELL_BASENAMES
