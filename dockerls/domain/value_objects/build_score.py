from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dockerls.domain.entities.build_validation import ValidationResult
    from dockerls.domain.entities.scan_result import ScanResult

# The Dockerfile's own hygiene and the runtime image's vulnerabilities are
# different kinds of evidence, so neither is allowed to hide the other. The
# scan carries the larger weight because a shipped CVE is a fact about the
# artifact, while a validation finding is a fact about how it was written.
DOCKERFILE_WEIGHT = 0.4
SCAN_WEIGHT = 0.6

CRITICAL_PENALTY = 25.0
HIGH_PENALTY = 8.0
MEDIUM_PENALTY = 2.0
LOW_PENALTY = 0.2


class BuildTier(StrEnum):
    S = "S"
    A = "A"
    B = "B"
    C = "C"


# The obligation each tier places on the reader, stated by the domain so
# the CLI and the exporters quote one source instead of three copies.
TIER_ADVICE: dict[BuildTier, str] = {
    BuildTier.S: "hardened -- ready for production",
    BuildTier.A: "production-ready",
    BuildTier.B: "conditional -- requires human review before production use",
    BuildTier.C: "not production ready",
}


class BuildScore:
    """Combined verdict on one build: how it was written *and* what shipped.

    A build with a spotless Dockerfile that produces an image full of
    CRITICALs is not a good build, and neither is a clean image built from
    a Dockerfile that bakes a token into an ENV layer. Scoring both and
    weighting them keeps either failure visible.
    """

    def __init__(
        self,
        validation: ValidationResult,
        scan: ScanResult | None = None,
    ):
        self._validation = validation
        self._scan = scan
        self._dockerfile_score = validation.score
        self._scan_score = _score_scan(scan) if scan is not None else None
        self._value = self._combine()

    @property
    def dockerfile_score(self) -> float:
        return self._dockerfile_score

    @property
    def scan_score(self) -> float | None:
        """None when no scan ran -- deliberately not 0 and not 100, so a
        report can say "not scanned" instead of implying a measurement."""
        return self._scan_score

    @property
    def value(self) -> float:
        return self._value

    @property
    def tier(self) -> BuildTier:
        if self._scan is not None:
            # A CRITICAL in the shipped image caps the tier regardless of
            # how good the arithmetic looks: no weighted average may
            # present a knowingly-vulnerable image as production-ready.
            if self._scan.critical_count:
                return BuildTier.C
            if self._scan.high_count > 3:
                return BuildTier.C
        if self._validation.failures:
            # An unmet CRITICAL/HIGH rule caps the tier the same way: the
            # worse of the two verdicts wins, never the flattering one.
            return max(self._tier_from_score(), BuildTier.B, key=_TIER_ORDER.index)
        return self._tier_from_score()

    @property
    def advice(self) -> str:
        return TIER_ADVICE[self.tier]

    @property
    def production_ready(self) -> bool:
        return self.tier in (BuildTier.S, BuildTier.A)

    def _tier_from_score(self) -> BuildTier:
        if self._value >= 95:
            return BuildTier.S
        if self._value >= 85:
            return BuildTier.A
        if self._value >= 70:
            return BuildTier.B
        return BuildTier.C

    def _combine(self) -> float:
        if self._scan_score is None:
            return self._dockerfile_score
        combined = self._dockerfile_score * DOCKERFILE_WEIGHT + self._scan_score * SCAN_WEIGHT
        return max(0.0, min(100.0, round(combined, 1)))


_TIER_ORDER = [BuildTier.S, BuildTier.A, BuildTier.B, BuildTier.C]


def _score_scan(scan: ScanResult) -> float:
    """0-100 rating of the shipped image's vulnerabilities alone."""
    penalty = (
        scan.critical_count * CRITICAL_PENALTY
        + scan.high_count * HIGH_PENALTY
        + scan.medium_count * MEDIUM_PENALTY
        + scan.low_count * LOW_PENALTY
    )
    return max(0.0, min(100.0, round(100.0 - penalty, 1)))
