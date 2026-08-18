"""How much the evidence behind a verdict is worth.

Every number this tool prints is the output of a chain: discover a
candidate, resolve it to a digest, scan it, cross-check it with a second
scanner, read its configuration. Links in that chain break routinely -- a
registry rate-limits, a second scanner is not installed, a catalogue is
stale -- and the result is still a table full of numbers. Without a
confidence signal, a score produced from one scanner on an unresolved tag is
rendered identically to one produced from two agreeing scanners on a pinned
digest, and the reader has no way to tell them apart.

The rule the rest of this codebase is built on gets its final expression
here: **a technical failure never becomes a security statement.** A scan
that did not complete is UNVERIFIED, which is not a bad score -- it is the
absence of a score, and the ranking layer refuses to recommend it at all.

The four levels:

* `UNVERIFIED` -- no completed scan. Nothing may be concluded, in either
  direction. This is a floor: no other signal can lift a candidate out of it.
* `LOW` -- scanned, but with a material problem: two scanners disagreed
  substantially, or the reference could not be pinned to a digest and the
  registry could not confirm it.
* `MEDIUM` -- scanned and consistent, with some evidence missing (no second
  scanner, no digest, or thin hardening coverage).
* `HIGH` -- scanned, pinned to a digest, confirmed in its registry, and
  corroborated by a second scanner that agreed.
"""

from __future__ import annotations

from enum import StrEnum
from typing import NamedTuple


class Confidence(StrEnum):
    UNVERIFIED = "UNVERIFIED"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    @property
    def is_recommendable(self) -> bool:
        """Whether a candidate at this confidence may be presented as a pick.

        UNVERIFIED never is. LOW may be shown -- with its reasons -- but the
        ranking layer will not put it above a comparable MEDIUM/HIGH result.
        """
        return self is not Confidence.UNVERIFIED


#: Ordering for comparisons, worst first. Written out rather than relying on
#: declaration order, so a future level inserted in the middle cannot
#: silently reorder existing comparisons.
CONFIDENCE_ORDER: tuple[Confidence, ...] = (
    Confidence.UNVERIFIED,
    Confidence.LOW,
    Confidence.MEDIUM,
    Confidence.HIGH,
)


def confidence_rank(level: Confidence) -> int:
    return CONFIDENCE_ORDER.index(level)


class ConfidenceInputs(NamedTuple):
    """The facts that decide a confidence level.

    A plain record rather than a reference to the analysis DTO: the domain
    must not depend on the application layer, and stating the inputs
    explicitly makes the rule below auditable in one screen.
    """

    #: The primary scan completed and produced a parsed result.
    scan_verified: bool
    #: A second scanner ran and produced a comparable result.
    cross_validated: bool = False
    #: A second scanner ran and disagreed materially with the first.
    scanners_disagree: bool = False
    #: The candidate is pinned to a manifest digest.
    digest_resolved: bool = False
    #: The registry that owns the reference confirmed the tag exists.
    #: Tri-state upstream (None = not checked); False is a real refutation.
    registry_verified: bool | None = None
    #: Share of the hardening model that could be determined, 0.0-1.0.
    hardening_coverage: float = 0.0


#: Hardening coverage below which the evidence is considered thin. Matches
#: the reporting threshold of the hardening model itself, so a score that is
#: not worth printing cannot silently prop up a HIGH confidence.
THIN_COVERAGE = 0.25


class ConfidenceAssessment:
    """Derives a confidence level and the reasons behind it."""

    def __init__(self, inputs: ConfidenceInputs):
        self._inputs = inputs
        self._reasons: list[str] = []
        self._level = self._assess()

    @property
    def level(self) -> Confidence:
        return self._level

    @property
    def reasons(self) -> list[str]:
        """Why this level, in the reader's terms. Never empty."""
        return list(self._reasons)

    def _assess(self) -> Confidence:
        i = self._inputs

        # The floor. Checked first and returned immediately: nothing below
        # is allowed to reason its way past a missing measurement.
        if not i.scan_verified:
            self._reasons.append("no completed scan: nothing was measured")
            return Confidence.UNVERIFIED

        if i.registry_verified is False:
            self._reasons.append("the registry that owns this reference does not have this tag")
            return Confidence.LOW

        if i.scanners_disagree:
            self._reasons.append("two scanners disagreed materially on the vulnerability counts")
            return Confidence.LOW

        if not i.digest_resolved and i.registry_verified is not True:
            self._reasons.append("reference is not pinned to a digest and was not confirmed")
            return Confidence.LOW

        gaps: list[str] = []
        if not i.cross_validated:
            gaps.append("only one scanner ran")
        if not i.digest_resolved:
            gaps.append("no manifest digest resolved")
        if i.hardening_coverage < THIN_COVERAGE:
            gaps.append("little of the image configuration could be inspected")

        if gaps:
            self._reasons.extend(gaps)
            return Confidence.MEDIUM

        self._reasons.append("scanned, pinned to a digest, confirmed in its registry")
        if i.cross_validated:
            self._reasons.append("corroborated by a second scanner that agreed")
        return Confidence.HIGH
