"""Attack surface: how much an attacker inherits after reaching the container.

Distinct from hardening, and distinct again from vulnerabilities. Hardening
asks "is this configured defensively"; attack surface asks "if code
execution happens inside this container, what is already there to use". A
shell, a package manager, a compiler and a network fetcher are each a rung
on that ladder, and none of them is a CVE.

**Size is not surface.** A 900 MB image built from a single statically
linked binary has a smaller attack surface than a 40 MB image carrying
busybox, apk and curl. Bytes are therefore not scored here at all; package
*count* is, because a package is a piece of installed functionality, and
capabilities are, because they are what the functionality can do.

The scale runs 0 (nothing found that expands surface) to 100 (every scored
item present). Like hardening, it is computed over determined facts only and
reports its coverage, so an image nobody could inspect reads as "unknown",
never as "clean".
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from dockerls.domain.entities.image_facts import HardeningFacts
    from dockerls.domain.value_objects.tristate import Tristate

#: Weights, highest first. A package manager outweighs a shell: a shell lets
#: an attacker use what is already installed, while a package manager lets
#: them install whatever is missing.
PACKAGE_MANAGER_WEIGHT = 25.0
SHELL_WEIGHT = 20.0
DEBUG_TOOLS_WEIGHT = 15.0
SETUID_WEIGHT = 15.0
ROOT_DEFAULT_WEIGHT = 15.0
PACKAGE_VOLUME_WEIGHT = 10.0

TOTAL_WEIGHT = (
    PACKAGE_MANAGER_WEIGHT
    + SHELL_WEIGHT
    + DEBUG_TOOLS_WEIGHT
    + SETUID_WEIGHT
    + ROOT_DEFAULT_WEIGHT
    + PACKAGE_VOLUME_WEIGHT
)

#: Package count at which the volume term saturates. A runtime image with a
#: few hundred packages carries a large amount of code nobody audited.
PACKAGE_VOLUME_CEILING = 400

#: Below this share of determined weight the number is not reported, for the
#: same reason as in the hardening model: it would look like a measurement.
MIN_REPORTABLE_COVERAGE = 0.25


class SurfaceItem(NamedTuple):
    """One scored element of the surface, kept so the score can explain itself."""

    name: str
    weight: float
    #: Surface contributed, 0.0 to `weight`.
    contributed: float
    determined: bool
    detail: str = ""


class AttackSurfaceScore:
    """0-100 where **higher means more surface**, over determined facts only.

    The inverted direction relative to every other score in this codebase is
    deliberate and is stated everywhere the number is rendered: "attack
    surface 80" must never be mistaken for "80% good".
    """

    def __init__(self, facts: HardeningFacts):
        self._items = _surface_items(facts)
        determined = [item for item in self._items if item.determined]
        self._available = sum(item.weight for item in determined)
        self._contributed = sum(item.contributed for item in determined)
        self._value = (
            round(100.0 * self._contributed / self._available, 1) if self._available > 0 else 0.0
        )

    @property
    def value(self) -> float:
        return self._value

    @property
    def coverage(self) -> float:
        return round(self._available / TOTAL_WEIGHT, 3)

    @property
    def is_reportable(self) -> bool:
        return self.coverage >= MIN_REPORTABLE_COVERAGE

    @property
    def items(self) -> list[SurfaceItem]:
        return list(self._items)

    @property
    def present(self) -> list[str]:
        """Surface elements confirmed present, for the explanation text."""
        return [
            item.detail or item.name
            for item in self._items
            if item.determined and item.contributed > 0.0
        ]

    @property
    def absent(self) -> list[str]:
        """Surface elements confirmed absent -- a genuine finding, not a default."""
        return [
            item.detail or item.name
            for item in self._items
            if item.determined and item.contributed <= 0.0
        ]


def _surface_items(facts: HardeningFacts) -> list[SurfaceItem]:
    return [
        _from_presence(
            "package-manager",
            PACKAGE_MANAGER_WEIGHT,
            facts.has_package_manager,
            present="package manager installed",
            absent="no package manager",
        ),
        _from_presence(
            "shell", SHELL_WEIGHT, facts.has_shell, present="shell present", absent="no shell"
        ),
        _from_presence(
            "debug-tools",
            DEBUG_TOOLS_WEIGHT,
            facts.has_debug_tools,
            present="compilers or network utilities present",
            absent="no compilers or network utilities",
        ),
        _from_presence(
            "setuid",
            SETUID_WEIGHT,
            facts.has_setuid,
            present="SUID/SGID binaries present",
            absent="no SUID/SGID binaries",
        ),
        _root_default(facts),
        _package_volume(facts),
    ]


def _from_presence(
    name: str, weight: float, state: Tristate, *, present: str, absent: str
) -> SurfaceItem:
    if not state.is_known:
        return SurfaceItem(name, weight, 0.0, determined=False)
    contributed = weight if state.is_true else 0.0
    return SurfaceItem(
        name, weight, contributed, determined=True, detail=present if state.is_true else absent
    )


def _root_default(facts: HardeningFacts) -> SurfaceItem:
    """Running as root multiplies what every other element is worth."""
    name = "root-default"
    if not facts.runs_as_non_root.is_known:
        return SurfaceItem(name, ROOT_DEFAULT_WEIGHT, 0.0, determined=False)
    if facts.runs_as_non_root.is_true:
        return SurfaceItem(
            name, ROOT_DEFAULT_WEIGHT, 0.0, determined=True, detail="runs unprivileged"
        )
    return SurfaceItem(
        name,
        ROOT_DEFAULT_WEIGHT,
        ROOT_DEFAULT_WEIGHT,
        determined=True,
        detail="runs as root by default",
    )


def _package_volume(facts: HardeningFacts) -> SurfaceItem:
    """Installed code volume, scaled linearly to a ceiling.

    Counted in packages, not bytes: the question is how much distinct
    installed functionality exists, and a single large binary is one thing
    to audit while three hundred small packages are three hundred.
    """
    name = "package-volume"
    count = facts.package_count
    if count is None:
        return SurfaceItem(name, PACKAGE_VOLUME_WEIGHT, 0.0, determined=False)
    ratio = min(1.0, max(0, count) / PACKAGE_VOLUME_CEILING)
    return SurfaceItem(
        name,
        PACKAGE_VOLUME_WEIGHT,
        round(PACKAGE_VOLUME_WEIGHT * ratio, 3),
        determined=True,
        detail=f"{count} installed packages",
    )
