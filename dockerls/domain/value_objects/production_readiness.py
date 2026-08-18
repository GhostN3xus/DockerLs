"""The one place that decides whether an image may go to production.

Before this module the decision was `tier in (A, B) and not is_eol`, computed
inside `SecurityTier` from the score alone. That expression cannot see
whether the scan finished, whether two scanners agreed, or whether anything
was verified at all -- so a `PARTIAL` scan with no findings in the targets it
managed to read produced a high score, tier A, and `production_ready = True`,
while the very same analysis reported `confidence = UNVERIFIED`.

An analysis that says both things is worse than one that says neither. The
field a CI gate reads is this one, so it is the field that must be hardest to
fool.

The policy is deliberately a *list of blockers* rather than a boolean with a
reason attached: a reader who is told "not production ready" immediately asks
why, and an image can fail for several independent causes at once. Every
blocker names itself in the reader's terms, and the same list feeds the
terminal, `--format json` and every exporter.

**Absence of evidence blocks; it does not excuse.** An unknown EOL status
does not prove the image is supported, an unresolved digest does not prove
the tag is stable, and a missing second scanner does not prove the first one
was right. None of those *penalise* the score -- there is nothing to penalise
-- but none of them may be spent as if it were a positive finding either.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from dockerls.domain.value_objects.confidence import Confidence, confidence_rank
from dockerls.domain.value_objects.security_tier import PRODUCTION_READY_TIERS, Tier
from dockerls.domain.value_objects.tristate import Tristate


class BlockingReason(StrEnum):
    """Why an image is not production ready. Stable codes, so a pipeline can
    branch on them without parsing prose."""

    NOT_MEASURED = "NOT_MEASURED"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    END_OF_LIFE = "END_OF_LIFE"
    CRITICAL_FINDINGS = "CRITICAL_FINDINGS"
    HIGH_FINDINGS = "HIGH_FINDINGS"
    UNFIXABLE_CRITICAL = "UNFIXABLE_CRITICAL"
    SCANNER_DIVERGENCE = "SCANNER_DIVERGENCE"
    TIER_TOO_LOW = "TIER_TOO_LOW"


#: What each code means where a human reads it.
EXPLANATIONS: dict[BlockingReason, str] = {
    BlockingReason.NOT_MEASURED: (
        "the scan did not complete, so nothing about this image was measured"
    ),
    BlockingReason.LOW_CONFIDENCE: (
        "the evidence behind this result has a material problem (see confidence reasons)"
    ),
    BlockingReason.END_OF_LIFE: "this release is end-of-life and will not receive security fixes",
    BlockingReason.CRITICAL_FINDINGS: "CRITICAL vulnerabilities are present",
    BlockingReason.HIGH_FINDINGS: "HIGH vulnerabilities are present",
    BlockingReason.UNFIXABLE_CRITICAL: "a CRITICAL vulnerability has no fix available",
    BlockingReason.SCANNER_DIVERGENCE: (
        "two scanners disagreed materially and the disagreement is unresolved"
    ),
    BlockingReason.TIER_TOO_LOW: "the security tier is below the production threshold",
}

#: Confidence below which no image is production ready, whatever its score.
#: MEDIUM is the floor rather than HIGH because HIGH requires a second
#: scanner, and refusing every single-scanner installation would make the
#: verdict a statement about the operator's toolchain instead of about the
#: image.
MINIMUM_CONFIDENCE = Confidence.MEDIUM


@dataclass(frozen=True)
class ReadinessInputs:
    """Everything the decision depends on, stated explicitly.

    A frozen record rather than a reference to the analysis DTO: the domain
    must not depend on the application layer, and listing the inputs is what
    makes the rule auditable without reading its callers.
    """

    tier: Tier
    confidence: Confidence
    scan_verified: bool
    #: Tri-state on purpose: `UNKNOWN` does not block (nothing says the
    #: release is dead) and does not excuse either -- it is surfaced, and it
    #: keeps confidence from reaching the top.
    eol: Tristate = Tristate.UNKNOWN
    critical_count: int = 0
    high_count: int = 0
    unfixable_critical_count: int = 0
    max_critical: int = 0
    max_high: int = 0
    has_material_divergence: bool = False


@dataclass(frozen=True)
class ProductionReadiness:
    """Applies the policy and reports every reason it failed."""

    inputs: ReadinessInputs
    blockers: list[BlockingReason] = field(default_factory=list)

    @classmethod
    def evaluate(cls, inputs: ReadinessInputs) -> ProductionReadiness:
        blockers: list[BlockingReason] = []

        # Measurement first. Everything below is a statement about findings,
        # and a statement about findings presupposes that somebody looked.
        if not inputs.scan_verified:
            blockers.append(BlockingReason.NOT_MEASURED)
        if confidence_rank(inputs.confidence) < confidence_rank(MINIMUM_CONFIDENCE):
            blockers.append(BlockingReason.LOW_CONFIDENCE)

        if inputs.eol.is_true:
            blockers.append(BlockingReason.END_OF_LIFE)
        if inputs.critical_count > inputs.max_critical:
            blockers.append(BlockingReason.CRITICAL_FINDINGS)
        if inputs.high_count > inputs.max_high:
            blockers.append(BlockingReason.HIGH_FINDINGS)
        if inputs.unfixable_critical_count > 0:
            blockers.append(BlockingReason.UNFIXABLE_CRITICAL)
        if inputs.has_material_divergence:
            blockers.append(BlockingReason.SCANNER_DIVERGENCE)
        if inputs.tier not in PRODUCTION_READY_TIERS:
            blockers.append(BlockingReason.TIER_TOO_LOW)

        return cls(inputs=inputs, blockers=blockers)

    @property
    def is_ready(self) -> bool:
        return not self.blockers

    @property
    def reasons(self) -> list[str]:
        """The blockers in the reader's terms, in the order they were found."""
        return [EXPLANATIONS[reason] for reason in self.blockers]

    @property
    def codes(self) -> list[str]:
        return [reason.value for reason in self.blockers]
