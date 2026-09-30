"""Compatibility filters, applied before scans are spent.

`recommend` measures the tags it finds, so a filter that runs *before* the
scans decides how many minutes go on images nobody could use. Four filters:

* **platform** -- `os/architecture[/variant]`;
* **runtime version** -- `22`, `22.5`, `>=20,<23` or `20-22`;
* **distribution family** -- `alpine`, `debian`, `ubuntu`, `wolfi`, ...;
* **variant** -- `runtime` or `dev`.

The distinction the result must keep is *how each exclusion was decided*:

* **CONFIRMED** -- from data the source published: an image whose listing
  states the architectures it ships does not have the requested one; a scan
  measured a different distribution than the one requested (checked after the
  scan, on the scanner's own reading of the image).
* **HEURISTIC** -- from the *tag's name*. `22-alpine` is very likely Alpine
  and `-dev` very likely a development variant, but a tag name is a naming
  convention, not a measurement, and the result says so.

A candidate is excluded up front only when the evidence says it does not
match. A tag that simply does not say (`latest`, `lts`, a bare `22` for a
distribution question) is *kept*: excluding it would be guessing in the
direction that hides options. Whatever is kept but unproven is still checked
against the measurement afterwards where a measurement exists.

Pure: nothing here touches the network, disk or a scanner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from dockerls.domain.value_objects.platform import Platform

if TYPE_CHECKING:
    from collections.abc import Sequence

    from dockerls.domain.entities.image import DockerImage


class Basis(StrEnum):
    CONFIRMED = "CONFIRMED"
    HEURISTIC = "HEURISTIC"


class Variant(StrEnum):
    RUNTIME = "runtime"
    DEV = "dev"


#: Tokens of a tag that name a distribution family. Deliberately conservative:
#: a bare version tag (`22`) names none, and is therefore never excluded by a
#: distribution filter on this evidence alone.
_FAMILY_TOKENS: dict[str, str] = {
    "alpine": "alpine",
    "wolfi": "wolfi",
    "chainguard": "wolfi",
    "debian": "debian",
    "bookworm": "debian",
    "bullseye": "debian",
    "buster": "debian",
    "trixie": "debian",
    "slim": "debian",
    "ubuntu": "ubuntu",
    "jammy": "ubuntu",
    "noble": "ubuntu",
    "focal": "ubuntu",
    "distroless": "distroless",
}

#: Tokens that mark a development / debugging variant of a runtime image.
_DEV_TOKENS = frozenset({"dev", "debug", "sdk", "build", "builder", "devel", "development"})

_TOKEN_SPLIT = re.compile(r"[-_.:/]")
_VERSION_PREFIX = re.compile(r"^v?(\d+(?:\.\d+)*)")
_COMPARATOR = re.compile(r"^(>=|<=|==|>|<)\s*v?(\d+(?:\.\d+)*)$")
_RANGE = re.compile(r"^v?(\d+(?:\.\d+)*)\s*-\s*v?(\d+(?:\.\d+)*)$")
_PLAIN = re.compile(r"^v?(\d+(?:\.\d+)*)(?:\.x)?$")

_KNOWN_FAMILIES = frozenset(_FAMILY_TOKENS.values()) | {
    "rhel",
    "rocky",
    "almalinux",
    "amazon",
    "fedora",
}


class InvalidCriteriaError(ValueError):
    """A filter value that is not one of the accepted shapes."""


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def _tokens(image: DockerImage) -> list[str]:
    return [t for t in _TOKEN_SPLIT.split(f"{image.name}:{image.tag}".lower()) if t]


def family_of_tag(image: DockerImage) -> str:
    """The distribution family a tag *names*, or "" when it names none."""
    for token in _tokens(image):
        if token in _FAMILY_TOKENS:
            return _FAMILY_TOKENS[token]
    return ""


def variant_of_tag(image: DockerImage) -> Variant:
    """`dev` when the tag carries a development token, `runtime` otherwise.

    "Otherwise" is the weak half: the absence of a `-dev` marker is what a
    runtime image looks like, but it is also what an unmarked development
    image looks like -- which is why this is only ever a HEURISTIC.
    """
    return Variant.DEV if any(t in _DEV_TOKENS for t in _tokens(image)) else Variant.RUNTIME


def version_of_tag(tag: str) -> tuple[int, ...] | None:
    match = _VERSION_PREFIX.match(tag.strip().lower())
    return _version(match.group(1)) if match else None


@dataclass(frozen=True)
class VersionRange:
    """`22`, `22.5`, `>=20,<23` or `20-22`, as a predicate on a tag's version."""

    text: str
    _terms: tuple[tuple[str, tuple[int, ...]], ...]

    @classmethod
    def parse(cls, text: str) -> VersionRange:
        source = text.strip()
        if not source:
            raise InvalidCriteriaError("an empty runtime version")
        range_match = _RANGE.match(source)
        if range_match:
            low, high = _version(range_match.group(1)), _version(range_match.group(2))
            if low > high:
                raise InvalidCriteriaError(f"runtime range {text!r} is empty")
            # Inclusive on the *major* of the upper bound: `20-22` includes 22.x.
            return cls(source, ((">=", low), ("<<", high[:1])))
        terms: list[tuple[str, tuple[int, ...]]] = []
        for part in (p.strip() for p in source.split(",")):
            comparator = _COMPARATOR.match(part)
            plain = _PLAIN.match(part)
            if comparator:
                terms.append((comparator.group(1), _version(comparator.group(2))))
            elif plain and len(source.split(",")) == 1:
                terms.append(("prefix", _version(plain.group(1))))
            else:
                raise InvalidCriteriaError(
                    f"runtime version {text!r} is not 22, 22.5, 22.x, >=20,<23 or 20-22"
                )
        return cls(source, tuple(terms))

    def accepts(self, version: tuple[int, ...]) -> bool:
        for operator, bound in self._terms:
            width = len(bound)
            head = version[:width]
            if operator == "prefix" and head != bound:
                return False
            if operator == ">=" and version < bound:
                return False
            if operator == ">" and version <= bound:
                return False
            if operator == "<=" and version > bound:
                return False
            if operator == "<" and version >= bound:
                return False
            if operator == "==" and version != bound:
                return False
            if operator == "<<" and version[:1] > bound:
                return False
        return True


@dataclass(frozen=True)
class Exclusion:
    reference: str
    criterion: str
    reason: str
    basis: Basis


@dataclass(frozen=True)
class CandidateCriteria:
    platform: Platform | None = None
    runtime_version: VersionRange | None = None
    distro: str = ""
    variant: Variant | None = None

    @property
    def active(self) -> bool:
        return any((self.platform, self.runtime_version, self.distro, self.variant))

    @classmethod
    def build(
        cls,
        *,
        platform: str | None = None,
        runtime_version: str | None = None,
        distro: str | None = None,
        variant: str | None = None,
    ) -> CandidateCriteria:
        family = (distro or "").strip().lower()
        if family and family not in _KNOWN_FAMILIES:
            raise InvalidCriteriaError(
                f"unknown distribution family {distro!r}; use one of: "
                f"{', '.join(sorted(_KNOWN_FAMILIES))}"
            )
        try:
            chosen = Variant((variant or "").strip().lower()) if variant else None
        except ValueError:
            raise InvalidCriteriaError(f"unknown variant {variant!r}; use runtime or dev") from None
        return cls(
            platform=Platform.parse(platform) if platform else None,
            runtime_version=VersionRange.parse(runtime_version) if runtime_version else None,
            distro=family,
            variant=chosen,
        )

    def describe(self) -> str:
        parts = []
        if self.platform:
            parts.append(f"platform={self.platform}")
        if self.runtime_version:
            parts.append(f"runtime={self.runtime_version.text}")
        if self.distro:
            parts.append(f"distro={self.distro}")
        if self.variant:
            parts.append(f"variant={self.variant.value}")
        return ", ".join(parts) or "none"

    def evaluate(self, image: DockerImage) -> Exclusion | None:
        """Why `image` is excluded before any scan, or None to keep it."""
        reference = image.full_reference
        if self.platform is not None and image.available_architectures:
            offered = {a.lower() for a in image.available_architectures if a}
            if self.platform.architecture not in offered:
                return Exclusion(
                    reference,
                    "platform",
                    f"the listing publishes {', '.join(sorted(offered))} but not "
                    f"{self.platform.architecture}",
                    Basis.CONFIRMED,
                )
        if self.runtime_version is not None:
            version = version_of_tag(image.tag)
            if version is not None and not self.runtime_version.accepts(version):
                return Exclusion(
                    reference,
                    "runtime",
                    f"tag version {'.'.join(map(str, version))} is outside "
                    f"{self.runtime_version.text}",
                    Basis.HEURISTIC,
                )
        if self.distro:
            named = family_of_tag(image)
            if named and named != self.distro and not _family_compatible(named, self.distro):
                return Exclusion(
                    reference,
                    "distro",
                    f"the tag names {named}, not {self.distro}",
                    Basis.HEURISTIC,
                )
        if self.variant is not None and variant_of_tag(image) is not self.variant:
            return Exclusion(
                reference,
                "variant",
                f"the tag reads as a {variant_of_tag(image).value} image, not {self.variant.value}",
                Basis.HEURISTIC,
            )
        return None

    def confirm(self, image: DockerImage, os_family: str) -> Exclusion | None:
        """Check a *measured* candidate against the distribution filter.

        The scanner reads the package database inside the image, so its answer
        replaces what the tag name suggested -- in both directions: it can
        exclude a candidate the tag's name let through, and it is what makes
        an "alpine" tag that is not Alpine visible.
        """
        if not self.distro or not os_family:
            return None
        measured = os_family.strip().lower()
        if measured == self.distro or _family_compatible(measured, self.distro):
            return None
        return Exclusion(
            image.full_reference,
            "distro",
            f"the scanner measured {measured}, not {self.distro}",
            Basis.CONFIRMED,
        )


def _family_compatible(a: str, b: str) -> bool:
    """Families a scanner and a tag name spell differently: a `wolfi` image is
    what Chainguard's tags call `chainguard`, and RHEL rebuilds share a base."""
    groups = ({"wolfi", "chainguard"}, {"rhel", "redhat", "centos", "rocky", "almalinux"})
    return any(a in group and b in group for group in groups)


@dataclass
class FilterOutcome:
    kept: list[DockerImage]
    excluded: list[Exclusion] = field(default_factory=list)

    def explain_empty(self, criteria: CandidateCriteria, discovered: int) -> str:
        """Why nothing is left, for the reader who asked for too much."""
        by_criterion: dict[str, int] = {}
        for item in self.excluded:
            by_criterion[item.criterion] = by_criterion.get(item.criterion, 0) + 1
        breakdown = ", ".join(f"{n} by {c}" for c, n in sorted(by_criterion.items()))
        heuristic = sum(1 for e in self.excluded if e.basis is Basis.HEURISTIC)
        note = (
            f" {heuristic} of those rest on tag names, not measurements: loosen or drop the "
            "filter if a tag was misread."
            if heuristic
            else ""
        )
        return (
            f"No candidate matches the filters ({criteria.describe()}): "
            f"{len(self.excluded)} of {discovered} discovered tags were excluded "
            f"({breakdown}).{note}"
        )


def apply_criteria(images: Sequence[DockerImage], criteria: CandidateCriteria) -> FilterOutcome:
    """Split `images` into those that stay in play and those excluded, with why."""
    if not criteria.active:
        return FilterOutcome(kept=list(images))
    kept: list[DockerImage] = []
    excluded: list[Exclusion] = []
    for image in images:
        exclusion = criteria.evaluate(image)
        if exclusion is None:
            kept.append(image)
        else:
            excluded.append(exclusion)
    return FilterOutcome(kept=kept, excluded=excluded)
