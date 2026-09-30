"""What changing base images actually costs, stated before it is recommended.

A tool that ranks images and stops there is only half-useful, because the
expensive part of acting on the ranking is not choosing -- it is finding out,
three days later, that the native module your application depends on was
compiled against glibc and the "safer" image ships musl. The security
argument for a migration is easy; the compatibility argument is the one that
decides whether the migration happens.

So every suggestion this codebase makes travels with its costs. The rules
below are deliberately conservative in one direction: a trade-off is raised
whenever the evidence *permits* a problem, and compatibility is never
asserted. There is no analysis here -- and there could not be one -- that can
tell you your application still runs. The checklist exists because that
question can only be answered by running it.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from dockerls.domain.value_objects.tristate import Tristate

if TYPE_CHECKING:
    from dockerls.application.dto.analysis import ImageAnalysis

#: C library each distribution family ships. The musl/glibc split is the
#: single most common cause of a base-image migration failing: prebuilt
#: native extensions (Node's node-gyp output, Python wheels, Go cgo builds)
#: are linked against one and will not load under the other.
_LIBC_BY_FAMILY = {
    "alpine": "musl",
    "debian": "glibc",
    "ubuntu": "glibc",
    "wolfi": "glibc",
    "chainguard": "glibc",
    "redhat": "glibc",
    "rhel": "glibc",
    "centos": "glibc",
    "rocky": "glibc",
    "almalinux": "glibc",
    "amazon": "glibc",
    "fedora": "glibc",
    "opensuse": "glibc",
    "sles": "glibc",
    "photon": "glibc",
    "oracle": "glibc",
}

#: Package manager each family uses, so a Dockerfile that runs `apk add`
#: can be told it will need rewriting rather than discovering it at build
#: time.
_PACKAGE_MANAGER_BY_FAMILY = {
    "alpine": "apk",
    "wolfi": "apk",
    "chainguard": "apk",
    "debian": "apt",
    "ubuntu": "apt",
    "redhat": "dnf/yum",
    "rhel": "dnf/yum",
    "centos": "dnf/yum",
    "rocky": "dnf/yum",
    "almalinux": "dnf/yum",
    "amazon": "dnf/yum",
    "fedora": "dnf",
    "opensuse": "zypper",
    "sles": "zypper",
}


class MigrationPlan(BaseModel):
    """The case for one migration, with its costs and the work it implies."""

    from_reference: str
    to_reference: str
    #: Digest-pinned form of the target, when one was resolved. This is what
    #: should go in a Dockerfile: a tag can move, a digest cannot.
    to_pinned_reference: str = ""
    #: Change in security score. Negative means the "alternative" is worse,
    #: which is reported rather than hidden.
    score_delta: float = 0.0
    critical_delta: int = 0
    high_delta: int = 0
    improvements: list[str] = Field(default_factory=list)
    trade_offs: list[str] = Field(default_factory=list)
    checklist: list[str] = Field(default_factory=list)
    #: True only when *nothing measured or named* says the move is more than a
    #: patch-level swap: the same base distribution, the same C library, the
    #: same major version, the same platform. It is the absence of known
    #: incompatibilities, never a claim of compatibility -- see
    #: `unverified_compatibility`.
    direct_replacement: bool = False
    #: Each reason this move is not a drop-in replacement, tagged
    #: `[confirmed]` (from a measurement or the image's own published data)
    #: or `[heuristic]` (from a tag name).
    incompatibilities: list[str] = Field(default_factory=list)
    #: What could not be established either way, so is neither claimed nor
    #: excluded: it needs the application's own tests.
    unverified_compatibility: list[str] = Field(default_factory=list)


def plan_migration(current: ImageAnalysis, target: ImageAnalysis) -> MigrationPlan:
    """Compare two *measured* images and describe the move between them."""
    return MigrationPlan(
        from_reference=current.image.full_reference,
        to_reference=target.image.full_reference,
        to_pinned_reference=target.image.pinned_reference,
        score_delta=round(target.security_score - current.security_score, 1),
        critical_delta=target.scan.critical_count - current.scan.critical_count,
        high_delta=target.scan.high_count - current.scan.high_count,
        improvements=_improvements(current, target),
        trade_offs=_trade_offs(current, target),
        checklist=_checklist(current, target),
        direct_replacement=not _incompatibilities(current, target),
        incompatibilities=_incompatibilities(current, target),
        unverified_compatibility=_unverified_compatibility(current, target),
    )


def _improvements(current: ImageAnalysis, target: ImageAnalysis) -> list[str]:
    """Gains, each one a difference between two measurements."""
    gains: list[str] = []

    for label, before, after in (
        ("CRITICAL", current.scan.critical_count, target.scan.critical_count),
        ("HIGH", current.scan.high_count, target.scan.high_count),
        ("MEDIUM", current.scan.medium_count, target.scan.medium_count),
    ):
        if after < before:
            gains.append(f"{label}: {before} -> {after}")

    before_kev = sum(1 for v in current.scan.vulnerabilities if v.exploit_known)
    after_kev = sum(1 for v in target.scan.vulnerabilities if v.exploit_known)
    if after_kev < before_kev:
        gains.append(f"known-exploited (CISA KEV) findings: {before_kev} -> {after_kev}")

    if current.is_eol and not target.is_eol:
        gains.append("target is still supported; the current image is end-of-life")
    if target.is_lts and not current.is_lts:
        gains.append("target is a long-term-support release")

    if target.facts.runs_as_non_root.is_true and not current.facts.runs_as_non_root.is_true:
        gains.append("target runs as a non-root account by default")
    if (
        target.attack_surface.reportable
        and current.attack_surface.reportable
        and target.attack_surface.score < current.attack_surface.score
    ):
        gains.append(
            f"attack surface: {current.attack_surface.score:.0f} -> "
            f"{target.attack_surface.score:.0f} (lower is better)"
        )
    if (
        target.hardening.reportable
        and current.hardening.reportable
        and target.hardening.score > current.hardening.score
    ):
        gains.append(f"hardening: {current.hardening.score:.0f} -> {target.hardening.score:.0f}")
    if target.image.digest_known:
        gains.append("target can be pinned to an immutable digest")
    return _unique(gains)


def _trade_offs(current: ImageAnalysis, target: ImageAnalysis) -> list[str]:
    """Costs. Raised whenever the evidence permits a problem."""
    costs: list[str] = []

    # Regressions first: an "alternative" that is worse on a severity band
    # must say so before anything else.
    for label, before, after in (
        ("CRITICAL", current.scan.critical_count, target.scan.critical_count),
        ("HIGH", current.scan.high_count, target.scan.high_count),
    ):
        if after > before:
            costs.append(f"{label} findings increase: {before} -> {after}")

    costs.extend(_major_trade_off(current, target))
    costs.extend(_libc_trade_off(current, target))
    costs.extend(_package_manager_trade_off(current, target))
    costs.extend(_shell_trade_off(target))
    costs.extend(_user_trade_off(current, target))
    costs.extend(_entrypoint_trade_off(current, target))
    costs.extend(_native_libraries_trade_off(current, target))
    costs.extend(_architecture_trade_off(current, target))

    if target.image.source != current.image.source:
        costs.append(
            f"different publisher: {current.image.source} -> {target.image.source}; "
            "check licensing, support and pull authentication before adopting"
        )
    if target.confidence.value != "HIGH":
        costs.extend(target.confidence_reasons)
    costs.extend(target.facts.conflicts)

    declared = target.image.declared
    if declared is not None and declared.end_of_life:
        costs.append(f"target release is declared end-of-life on {declared.end_of_life}")
    return _unique(costs)


def _major_of(analysis: ImageAnalysis) -> int | None:
    """The major version a tag *names*, or None when it names none.

    `22-alpine` -> 22, `3.12.4-slim` -> 3, `latest` -> None. Read from the tag,
    so it is only a heuristic about what the image contains -- but a runtime
    tag that says 24 is very rarely a swap-in for one that says 22.
    """
    match = re.match(r"^v?(\d+)", analysis.image.tag.strip().lower())
    return int(match.group(1)) if match else None


def _major_trade_off(current: ImageAnalysis, target: ImageAnalysis) -> list[str]:
    before, after = _major_of(current), _major_of(target)
    if before is None or after is None:
        return []
    if before == after:
        return []
    direction = "upgrade" if after > before else "downgrade"
    return [
        f"major version {direction} ({before} -> {after}): not a direct replacement -- "
        "breaking changes between majors (removed APIs, changed defaults, dropped "
        "platforms) must be read in the release notes and tested"
    ]


def _user_trade_off(current: ImageAnalysis, target: ImageAnalysis) -> list[str]:
    """The account the container runs as, when both sides were measured."""
    before, after = current.facts.user.strip(), target.facts.user.strip()
    if not (
        current.facts.is_verified("runs_as_non_root")
        and target.facts.is_verified("runs_as_non_root")
    ):
        return []
    if before == after:
        return []
    return [
        f"default user changes ({before or 'root'} -> {after or 'root'}): file ownership, "
        "bound ports below 1024 and volume permissions may behave differently"
    ]


def _entrypoint_trade_off(current: ImageAnalysis, target: ImageAnalysis) -> list[str]:
    """ENTRYPOINT/CMD, from the registry's config on both sides."""
    if not (current.facts.is_verified("entrypoint") and target.facts.is_verified("entrypoint")):
        return []
    if (current.facts.entrypoint, current.facts.cmd) == (target.facts.entrypoint, target.facts.cmd):
        return []
    return [
        "entrypoint or default command differ between the two images: anything that "
        "relies on the old defaults (or overrides them) needs to be checked"
    ]


def _native_libraries_trade_off(current: ImageAnalysis, target: ImageAnalysis) -> list[str]:
    """What a vulnerability scan can and cannot say about shared libraries.

    The scan lists packages *with findings*, not every library in the image, so
    it cannot show that a shared object your application links against is (or
    is not) present in the target. That is stated instead of implied.
    """
    if _family_of(current) == _family_of(target) and _family_of(current):
        return []
    return [
        "the set of shared libraries differs between different base images; the scan only "
        "sees packages with findings, so it cannot confirm that the native libraries your "
        "application links against exist in the target (check with `ldd`)"
    ]


def _incompatibilities(current: ImageAnalysis, target: ImageAnalysis) -> list[str]:
    """Reasons this is *not* a drop-in replacement, each tagged with its basis."""
    reasons: list[str] = []
    before, after = _major_of(current), _major_of(target)
    if before is not None and after is not None and before != after:
        reasons.append(f"[heuristic] major version {before} -> {after} (from the tags)")
    elif before is None or after is None:
        reasons.append("[heuristic] a tag names no version, so the major cannot be compared")
    family_before, family_after = _family_of(current), _family_of(target)
    if not family_before or not family_after:
        reasons.append("[unknown] a base distribution was not identified by the scanner")
    elif family_before != family_after:
        reasons.append(f"[confirmed] base distribution {family_before} -> {family_after}")
    libc_before, libc_after = _libc_of(current), _libc_of(target)
    if libc_before and libc_after and libc_before != libc_after:
        reasons.append(f"[confirmed] C library {libc_before} -> {libc_after}")
    platform_before, platform_after = current.image.platform, target.image.platform
    if platform_before and platform_after and platform_before != platform_after:
        reasons.append(f"[confirmed] platform {platform_before} -> {platform_after}")
    if current.image.source != target.image.source:
        reasons.append(f"[confirmed] publisher {current.image.source} -> {target.image.source}")
    return reasons


def _unverified_compatibility(current: ImageAnalysis, target: ImageAnalysis) -> list[str]:
    """What nothing here could settle, listed rather than assumed away."""
    open_questions = [
        "whether your application starts and behaves the same (only its own tests can say)",
    ]
    if not (current.facts.is_verified("entrypoint") and target.facts.is_verified("entrypoint")):
        open_questions.append("entrypoint and default command (one side was not inspected)")
    if not (
        current.facts.is_verified("runs_as_non_root")
        and target.facts.is_verified("runs_as_non_root")
    ):
        open_questions.append("the default user (one side was not inspected)")
    open_questions.append("which native libraries your application links against")
    return open_questions


def _libc_trade_off(current: ImageAnalysis, target: ImageAnalysis) -> list[str]:
    """The musl/glibc question, answered only when both sides are known."""
    before = _libc_of(current)
    after = _libc_of(target)
    if not before or not after:
        # One side's base distribution was not identified, so nothing can be
        # said. Saying "compatible" here is the error this whole module is
        # written to avoid.
        return [
            "the base distribution of one side could not be identified: "
            "assume the C library may differ and test native dependencies"
        ]
    if before == after:
        return []
    return [
        f"C library changes ({before} -> {after}): prebuilt native modules, "
        "wheels and cgo binaries linked against the old one will not load and "
        "must be rebuilt"
    ]


def _package_manager_trade_off(current: ImageAnalysis, target: ImageAnalysis) -> list[str]:
    before = _PACKAGE_MANAGER_BY_FAMILY.get(_family_of(current), "")
    after = _PACKAGE_MANAGER_BY_FAMILY.get(_family_of(target), "")
    if not before or not after or before == after:
        return []
    return [
        f"package manager changes ({before} -> {after}): every install step in "
        "your Dockerfile needs rewriting, and package names differ between them"
    ]


def _shell_trade_off(target: ImageAnalysis) -> list[str]:
    """A missing shell is a hardening win and an operational cost at once."""
    facts = target.facts
    if facts.has_shell is Tristate.FALSE:
        return [
            "target has no shell: `docker exec` debugging, shell-form RUN/CMD "
            "and entrypoint scripts will not work"
        ]
    if facts.has_package_manager is Tristate.FALSE:
        return [
            "target has no package manager: anything your build installs at "
            "runtime must move into a builder stage"
        ]
    return []


def _architecture_trade_off(current: ImageAnalysis, target: ImageAnalysis) -> list[str]:
    """Flag architectures the current image supports and the target may not."""
    before = {a for a in current.image.available_architectures if a}
    after = {a for a in target.image.available_architectures if a}
    if not before or not after:
        return []
    lost = sorted(before - after)
    if not lost:
        return []
    return [
        f"target does not publish {', '.join(lost)}: check every platform your deployment targets"
    ]


def _checklist(current: ImageAnalysis, target: ImageAnalysis) -> list[str]:
    """Ordered steps to validate the move, specific where the facts allow.

    Generic enough to be honest, specific enough to be worth following: the
    libc and non-root steps only appear when the evidence says they apply.
    """
    steps = [
        f"rebuild your image against {target.image.pinned_reference}",
    ]
    if _libc_of(current) and _libc_of(target) and _libc_of(current) != _libc_of(target):
        steps.append(
            f"rebuild every native dependency for {_libc_of(target)} "
            "(clear prebuilt binaries and caches first)"
        )
    steps.append("run the unit test suite against the rebuilt image")
    steps.append("run the integration test suite against the rebuilt image")
    if target.facts.runs_as_non_root.is_true and not current.facts.runs_as_non_root.is_true:
        steps.append(
            f"fix filesystem ownership for the non-root account "
            f"({target.facts.user or 'the image default'}): writes to paths owned "
            "by root will now fail"
        )
    if target.facts.has_shell is Tristate.FALSE:
        steps.append("replace shell-form CMD/ENTRYPOINT and entrypoint scripts with exec form")
    steps.append("re-scan the resulting image (`dockerls analyze <your-image>`)")
    steps.append("verify runtime behaviour under production-like load")
    steps.append("deploy to a canary before rolling out")
    return steps


def _family_of(analysis: ImageAnalysis) -> str:
    """Base distribution, preferring the scanner's answer over any other.

    The scanner reads the package database inside the image, which is the
    only one of the available signals that cannot be wrong about what the
    image actually is.
    """
    family = (analysis.scan.os_family or analysis.facts.os_family or "").strip().lower()
    return family


def _libc_of(analysis: ImageAnalysis) -> str:
    return _LIBC_BY_FAMILY.get(_family_of(analysis), "")


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            unique.append(item)
    return unique
