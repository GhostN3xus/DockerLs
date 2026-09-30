"""How much a run is asked to do: `quick`, `standard` or `audit`.

A profile is a named bundle of the knobs that already exist -- how many tags
are measured, whether a second scanner confirms the finalists, whether tags
are checked against their registry, how much threat intelligence is gathered
-- so that "fast enough for a pull request" and "complete enough for an
audit" are one word instead of six flags.

Three rules keep a profile from becoming a way to fake an answer:

* **Skipped is pending, never approved.** A check a profile does not perform
  is listed as *not performed* in the result, and the analysis is evaluated
  exactly as it is when the operator passes `--no-cross-validate` today: no
  second opinion means lower confidence, not a free pass.
* **Explicit flags win.** Precedence, highest first: an explicit command-line
  flag, then the profile, then the configuration file / environment, then the
  built-in default. A profile is itself an explicit choice on the command
  line, so it overrides ambient configuration; a specific flag overrides it.
* **No profile means today's behaviour.** Without `--profile` nothing here is
  applied. `standard` spells the built-in defaults out, so choosing it is
  equivalent to choosing nothing on a default configuration.

The numbers below are starting points, not measurements: `docs/PERFORMANCE.md`
says which were measured on which machine and which were not, and
`benchmarks/bench_profiles.py` reproduces the measurable ones.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from dockerls.domain.value_objects.scan_plan import DEFAULT_SCAN_BUDGET

#: The checks a run may not perform, spelled once so the profile that skips
#: them and the use case that reports them cannot drift apart.
CHECK_CROSS_VALIDATION = "cross-validation with a second scanner"
CHECK_TAG_VERIFICATION = "tag existence check against the source registry"
CHECK_INSPECTION = "OCI config inspection of the finalists"


class Enrichment(StrEnum):
    """Which candidates get threat-intelligence lookups."""

    #: Every measured candidate (today's behaviour).
    ALL = "all"
    #: Only the finalists. The others stay UNKNOWN for KEV/EPSS/Exploit-DB/OSV,
    #: and the result says the comparison between them is limited by that.
    FINALISTS = "finalists"


class ProfileName(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    AUDIT = "audit"


@dataclass(frozen=True)
class ExecutionProfile:
    name: ProfileName
    summary: str
    #: Tags actually measured; 0 measures every tag discovered.
    scan_budget: int
    #: A second, independent scanner re-measures the finalists.
    cross_validate: bool
    #: Each finalist's tag is confirmed against the registry that owns it.
    verify_tags: bool
    #: The finalists' OCI config is read for hardening facts.
    inspect_finalists: bool
    enrichment: Enrichment

    def not_performed(self) -> list[str]:
        """Checks this profile does not do, named for the reader.

        These become the result's *pending checks*: absence of a check is a
        stated limitation, never silently equivalent to a passed one.
        """
        skipped: list[str] = []
        if not self.cross_validate:
            skipped.append(f"{CHECK_CROSS_VALIDATION} (not run in this profile)")
        if not self.verify_tags:
            skipped.append(f"{CHECK_TAG_VERIFICATION} (not run in this profile)")
        if not self.inspect_finalists:
            skipped.append(f"{CHECK_INSPECTION} (not run in this profile)")
        if self.enrichment is Enrichment.FINALISTS:
            skipped.append("threat intelligence for candidates outside the finalists")
        return skipped


PROFILES: dict[ProfileName, ExecutionProfile] = {
    ProfileName.QUICK: ExecutionProfile(
        name=ProfileName.QUICK,
        summary=(
            "a few representative candidates, one scanner, cheap checks only; "
            "optional verification is reported as not performed"
        ),
        scan_budget=8,
        cross_validate=False,
        verify_tags=True,
        inspect_finalists=True,
        enrichment=Enrichment.FINALISTS,
    ),
    ProfileName.STANDARD: ExecutionProfile(
        name=ProfileName.STANDARD,
        summary="the built-in defaults: balanced coverage, latency and verification",
        scan_budget=DEFAULT_SCAN_BUDGET,
        cross_validate=True,
        verify_tags=True,
        inspect_finalists=True,
        enrichment=Enrichment.ALL,
    ),
    ProfileName.AUDIT: ExecutionProfile(
        name=ProfileName.AUDIT,
        summary=(
            "every discovered tag is measured, and the finalists are cross-validated and inspected"
        ),
        scan_budget=0,
        cross_validate=True,
        verify_tags=True,
        inspect_finalists=True,
        enrichment=Enrichment.ALL,
    ),
}


class UnknownProfileError(ValueError):
    """`--profile` named something that is not a profile."""


def resolve_profile(name: str | None) -> ExecutionProfile | None:
    """The named profile, or None when none was asked for (today's behaviour)."""
    if name is None or not name.strip():
        return None
    try:
        return PROFILES[ProfileName(name.strip().lower())]
    except ValueError:
        choices = ", ".join(p.value for p in ProfileName)
        raise UnknownProfileError(f"unknown profile {name!r}; use one of: {choices}") from None
