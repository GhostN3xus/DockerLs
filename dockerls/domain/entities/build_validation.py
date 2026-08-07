from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from dockerls.domain.entities.vulnerability import Severity


class CheckStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - a check verdict, not a credential
    WARN = "WARN"
    FAIL = "FAIL"
    # The rule could not be evaluated (e.g. no build context on disk).
    # Deliberately distinct from PASS: "not checked" is not "clean".
    SKIP = "SKIP"


class HardeningLevel(StrEnum):
    """How much of the rule set is allowed to block a build.

    The rule *findings* are identical at every level -- only the decision
    to stop the build changes. A relaxed run still reports the same
    MEDIUM finding it would have blocked on under `strict`.
    """

    STRICT = "strict"
    STANDARD = "standard"
    RELAXED = "relaxed"

    @property
    def blocking_severities(self) -> frozenset[Severity]:
        if self is HardeningLevel.STRICT:
            return frozenset({Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM})
        if self is HardeningLevel.RELAXED:
            return frozenset({Severity.CRITICAL})
        return frozenset({Severity.CRITICAL, Severity.HIGH})


# What one failed check costs the Dockerfile score. Chosen so a single
# CRITICAL (a secret baked into the image) cannot be offset by passing
# every cosmetic rule, while a handful of LOW findings barely move it.
SEVERITY_PENALTY: dict[Severity, float] = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
    Severity.UNKNOWN: 1.0,
}


class ValidationCheck(BaseModel):
    """The outcome of one security rule against one Dockerfile."""

    check: str
    title: str = ""
    status: CheckStatus
    severity: Severity = Severity.MEDIUM
    message: str = ""
    # 0 when the finding is about the file as a whole rather than a line.
    line: int = 0
    fix: str = ""

    @property
    def failed(self) -> bool:
        return self.status in (CheckStatus.FAIL, CheckStatus.WARN)

    @property
    def penalty(self) -> float:
        if not self.failed:
            return 0.0
        return SEVERITY_PENALTY.get(self.severity, 1.0)


class ValidationResult(BaseModel):
    """Every rule's verdict for one Dockerfile, plus the derived score.

    `blocking` is computed against a hardening level rather than stored per
    check, so the same findings can be rendered as advisory in one run and
    as build-stopping in another without re-running the rules.
    """

    dockerfile_path: str = ""
    checks: list[ValidationCheck] = Field(default_factory=list)
    hardening_level: HardeningLevel = HardeningLevel.STANDARD
    parse_errors: list[str] = Field(default_factory=list)

    @property
    def passed(self) -> list[ValidationCheck]:
        return [c for c in self.checks if c.status is CheckStatus.PASS]

    @property
    def warnings(self) -> list[ValidationCheck]:
        return [c for c in self.checks if c.status is CheckStatus.WARN]

    @property
    def failures(self) -> list[ValidationCheck]:
        return [c for c in self.checks if c.status is CheckStatus.FAIL]

    @property
    def skipped(self) -> list[ValidationCheck]:
        return [c for c in self.checks if c.status is CheckStatus.SKIP]

    @property
    def evaluated_count(self) -> int:
        """Rules that actually ran. Skipped rules are excluded from the
        "9/12 passed" denominator -- counting them would let an unreadable
        build context inflate the pass rate."""
        return len([c for c in self.checks if c.status is not CheckStatus.SKIP])

    @property
    def blocking(self) -> list[ValidationCheck]:
        """Findings severe enough to stop the build at this level."""
        severities = self.hardening_level.blocking_severities
        return [c for c in self.checks if c.failed and c.severity in severities]

    @property
    def has_blocking_findings(self) -> bool:
        return bool(self.blocking)

    @property
    def score(self) -> float:
        """0-100 rating of the Dockerfile itself, independent of any scan.

        Every rule contributes: an unevaluated (SKIP) rule neither helps
        nor hurts, a failed rule costs its severity penalty.
        """
        penalty = sum(c.penalty for c in self.checks)
        return max(0.0, min(100.0, round(100.0 - penalty, 1)))
