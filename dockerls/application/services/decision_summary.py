"""The answer to "what should I use, and how far can I trust that?".

Every command that ends in a recommendation used to render its own idea of a
verdict from the raw result, and none of them put the parts a reader needs to
decide in one place: which image, pinned to what, for which platform, why,
what is wrong with it, what is still unverified, how old the measurement and
the vulnerability database are, and whether the numbers were measured now or
reused. This builds that summary once, as data, so the terminal and the CI
output say the same thing.

Three rules about wording, because they are where such summaries lie:

* **"Best among what was measured", not "the best".** When coverage is not
  complete -- the time budget ended, a filter removed candidates, some scans
  failed -- the headline says the image is the best of the *measured*
  candidates, and says which part was not measured.
* **Three kinds of "not OK", kept apart.** A policy failure (the image was
  measured and does not meet the baseline), an incomplete verification (a
  check did not run, so the result cannot claim more), and an infrastructure
  failure (a scanner, database or registry failed, so nothing was measured)
  need different reactions; they are never merged into one "failed".
* **Nothing is claimed beyond the policy.** "Production ready" is copied from
  the central readiness policy, never inferred here; a score never appears
  without the blockers next to it; anything that could not be determined is
  the word "unknown".
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis

#: What each classified scan failure asks the operator to do.
CAUSE_ACTIONS = {
    "SCANNER_MISSING": "Install Trivy or Grype, then re-run (`dockerls doctor` checks for both).",
    "DB_INIT_FAILED": (
        "The vulnerability database could not be prepared: check network access to ghcr.io "
        "and re-run."
    ),
    "TIMEOUT": ("Scans exceeded the timeout: raise DOCKERLS_SCANNER_TIMEOUT or lower --workers."),
    "RATE_LIMITED": "Rate limited by the registry: run `dockerls login`, or retry later.",
    "AUTH_REQUIRED": "The registry requires credentials: run `dockerls login`.",
    "NOT_FOUND": "None of the tags could be pulled: check the image name.",
    "PLATFORM_UNAVAILABLE": "The image publishes no manifest for the requested platform.",
}


class Kind(StrEnum):
    #: The top candidate meets the baseline, coverage is complete, and the
    #: readiness policy passed it.
    RECOMMENDED = "RECOMMENDED"
    #: A measured candidate exists, but the result cannot be called a
    #: recommendation without qualification.
    BEST_MEASURED = "BEST_MEASURED"
    #: Nothing was measured.
    NONE = "NONE"


class Category(StrEnum):
    POLICY = "POLICY"
    INCOMPLETE = "INCOMPLETE"
    INFRASTRUCTURE = "INFRASTRUCTURE"


class DecisionSummary(BaseModel):
    schema_id: str = "dockerls.decision/1"
    kind: Kind = Kind.NONE
    headline: str = ""
    image: str = ""
    requested_reference: str = ""
    pinned_reference: str = ""
    measured_reference: str = ""
    platform: str = ""
    index_digest: str = ""
    identity_status: str = ""
    identity_note: str = ""
    reason: str = ""
    critical: int | None = None
    high: int | None = None
    medium: int | None = None
    low: int | None = None
    fixable: int | None = None
    total: int | None = None
    score: float | None = None
    #: Set (and `score` left None) when two scanners disagree about this image:
    #: a number two scanners contest is not shown as if it were settled.
    score_disputed: str = ""
    tier: str = ""
    production_ready: bool = False
    blockers: list[str] = Field(default_factory=list)
    blocker_reasons: list[str] = Field(default_factory=list)
    confidence: str = "UNKNOWN"
    confidence_reasons: list[str] = Field(default_factory=list)
    pending_checks: list[str] = Field(default_factory=list)
    completeness: str = "COMPLETE"
    measured_at: str = ""
    measurement_age_seconds: float | None = None
    db_revision: str = ""
    db_age_seconds: float | None = None
    origin: str = "unknown"
    scanner: str = ""
    scanner_version: str = ""
    #: Each entry starts with its category: `POLICY: ...`, `INCOMPLETE: ...`,
    #: `INFRASTRUCTURE: ...`.
    problems: list[str] = Field(default_factory=list)
    categories: list[Category] = Field(default_factory=list)
    next_action: str = ""


def age_seconds(timestamp: str, now: datetime | None = None) -> float | None:
    """Seconds since an ISO timestamp, or None when it is absent or unreadable.

    None is *unknown*, not zero: a measurement of unknown age is not a fresh
    one, and the renderers print it as "unknown".
    """
    if not timestamp:
        return None
    try:
        moment = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    delta = (now or datetime.now(tz=UTC)) - moment
    seconds = delta.total_seconds()
    return max(0.0, seconds)


def humanize_age(seconds: float | None) -> str:
    """`5 minutes`, `3 hours`, `2.1 days`, or `unknown`."""
    if seconds is None:
        return "unknown"
    if seconds < 90:
        return f"{int(seconds)} seconds"
    if seconds < 5400:
        return f"{int(seconds // 60)} minutes"
    if seconds < 48 * 3600:
        return f"{seconds / 3600:.0f} hours"
    return f"{seconds / 86400:.1f} days"


def _identity_note(analysis: ImageAnalysis) -> str:
    """Why the identity is (or is not) confirmed, without a leading verdict --
    the renderer says "not confirmed", this says why."""
    image = analysis.image
    if image.identity_confirmed:
        return "the registry confirmed this digest for the measured platform"
    return image.identity_limitation or "no registry answered for this tag"


def _fill_from_analysis(
    summary: DecisionSummary, analysis: ImageAnalysis, now: datetime | None
) -> None:
    scan = analysis.scan
    prov = analysis.provenance
    image = analysis.image
    summary.image = image.full_reference
    summary.requested_reference = prov.requested_reference or image.full_reference
    summary.pinned_reference = image.pinned_reference if image.identity_confirmed else ""
    summary.measured_reference = prov.measured_reference or scan.image_reference
    summary.platform = image.platform or prov.platform or scan.platform
    summary.index_digest = image.index_digest
    summary.identity_status = image.identity_status or "UNRESOLVED"
    summary.identity_note = _identity_note(analysis)
    summary.reason = analysis.why[0] if analysis.why else ""
    summary.critical = scan.critical_count
    summary.high = scan.high_count
    summary.medium = scan.medium_count
    summary.low = scan.low_count
    summary.fixable = scan.fixable_count
    summary.total = scan.total_count
    summary.score_disputed = analysis.scan_divergence
    summary.score = None if analysis.scan_divergence else analysis.security_score
    summary.tier = analysis.tier
    summary.production_ready = analysis.production_ready
    summary.blockers = list(analysis.readiness_blockers)
    summary.blocker_reasons = list(analysis.readiness_reasons)
    summary.confidence = analysis.confidence.value
    summary.confidence_reasons = list(analysis.confidence_reasons)
    summary.measured_at = prov.measured_at or scan.scan_timestamp
    summary.measurement_age_seconds = age_seconds(summary.measured_at, now)
    summary.db_revision = prov.db_revision
    summary.db_age_seconds = age_seconds(prov.db_revision, now)
    summary.origin = prov.origin
    summary.scanner = prov.scanner or scan.scanner
    summary.scanner_version = prov.scanner_version


def _problems(
    summary: DecisionSummary,
    *,
    baseline_met: bool | None,
    infrastructure: Counter[str],
    filters_note: str,
) -> None:
    problems: list[str] = []
    categories: list[Category] = []

    if summary.blockers:
        problems.append(f"{Category.POLICY}: not production ready ({', '.join(summary.blockers)})")
        categories.append(Category.POLICY)
    elif baseline_met is False and summary.kind is not Kind.NONE:
        problems.append(f"{Category.POLICY}: no candidate meets the configured baseline")
        categories.append(Category.POLICY)

    incomplete: list[str] = []
    if summary.completeness != "COMPLETE":
        incomplete.append(f"the run is {summary.completeness} (time budget)")
    incomplete.extend(summary.pending_checks)
    if filters_note:
        incomplete.append(filters_note)
    if summary.db_age_seconds is None and summary.kind is not Kind.NONE:
        incomplete.append("the age of the vulnerability database could not be determined")
    for item in incomplete:
        problems.append(f"{Category.INCOMPLETE}: {item}")
    if incomplete:
        categories.append(Category.INCOMPLETE)

    if infrastructure:
        causes = ", ".join(f"{kind} x{count}" for kind, count in infrastructure.most_common())
        problems.append(f"{Category.INFRASTRUCTURE}: scans failed ({causes})")
        categories.append(Category.INFRASTRUCTURE)

    summary.problems = problems
    summary.categories = categories


#: Failure causes that come from the tools and services around the image --
#: not from the image. `NOT_FOUND` and a missing platform are facts about the
#: image itself and are not infrastructure.
_INFRASTRUCTURE_KINDS = frozenset(
    {
        "DB_INIT_FAILED",
        "TIMEOUT",
        "SCANNER_MISSING",
        "RATE_LIMITED",
        "INVALID_OUTPUT",
        "AUTH_REQUIRED",
        "UNKNOWN",
    }
)


def _infrastructure(result: AnalysisResult) -> Counter[str]:
    """Scan failures that say nothing about the images (a tool, a database, a
    registry failed), as opposed to tags that simply do not exist."""
    return Counter(item.kind for item in result.unverified if item.kind in _INFRASTRUCTURE_KINDS)


def _next_action(summary: DecisionSummary, infrastructure: Counter[str], filters_note: str) -> str:
    if summary.kind is Kind.NONE:
        if filters_note:
            return "Loosen or drop the compatibility filters, then re-run."
        if infrastructure:
            dominant = infrastructure.most_common(1)[0][0]
            return CAUSE_ACTIONS.get(dominant, "Run with --verbose, or see the log file.")
        if summary.completeness != "COMPLETE":
            return "Re-run with a larger --time-budget, or without one."
        return "Nothing usable was found: check the image name and your sources."
    if summary.completeness != "COMPLETE":
        return (
            "This result is partial: re-run with a larger --time-budget (or none) before "
            "acting on it."
        )
    if infrastructure:
        dominant = infrastructure.most_common(1)[0][0]
        return CAUSE_ACTIONS.get(dominant, "Some scans failed: see the log file.")
    if summary.blockers:
        return (
            f"Do not treat {summary.image} as production ready: resolve "
            f"{', '.join(summary.blockers)} first, or pick a candidate without them."
        )
    if summary.pending_checks:
        return (
            "Complete the pending checks (for example `--profile audit`) before relying "
            "on this result."
        )
    if summary.pinned_reference:
        return (
            f"Pin `{summary.pinned_reference}` in your Dockerfile, build, then re-scan the "
            "result with `dockerls analyze`."
        )
    return "The identity could not be pinned: re-run when the registry is reachable."


def summarize_analysis(
    analysis: ImageAnalysis,
    *,
    completeness: str = "COMPLETE",
    pending_checks: list[str] | None = None,
    baseline_met: bool | None = None,
    kind: Kind | None = None,
    now: datetime | None = None,
) -> DecisionSummary:
    """The summary of one measured image (used by `analyze` and `compare`)."""
    summary = DecisionSummary(completeness=completeness, pending_checks=pending_checks or [])
    _fill_from_analysis(summary, analysis, now)
    summary.kind = kind or (
        Kind.RECOMMENDED
        if analysis.production_ready and completeness == "COMPLETE"
        else Kind.BEST_MEASURED
    )
    summary.headline = _analysis_headline(summary)
    _problems(summary, baseline_met=baseline_met, infrastructure=Counter(), filters_note="")
    summary.next_action = _next_action(summary, Counter(), "")
    return summary


def summarize_recommendation(
    result: AnalysisResult, *, now: datetime | None = None
) -> DecisionSummary:
    """The summary of a `recommend` run: the top candidate and the run's limits."""
    items = result.recommendations or result.alternatives
    summary = DecisionSummary(
        completeness=result.completeness, pending_checks=list(result.pending_checks)
    )
    infrastructure = _infrastructure(result)
    if items:
        top = items[0]
        _fill_from_analysis(summary, top, now)
        complete = result.completeness == "COMPLETE" and not result.filters_note
        summary.kind = (
            Kind.RECOMMENDED
            if result.baseline_met and top.production_ready and complete
            else Kind.BEST_MEASURED
        )
    else:
        summary.kind = Kind.NONE
    summary.headline = _headline(summary, baseline_met=result.baseline_met, result=result)
    _problems(
        summary,
        baseline_met=result.baseline_met,
        infrastructure=infrastructure,
        filters_note=result.filters_note,
    )
    summary.next_action = _next_action(summary, infrastructure, result.filters_note)
    return summary


def _analysis_headline(summary: DecisionSummary) -> str:
    """For one image the user asked about: a finding, never a recommendation."""
    if summary.completeness != "COMPLETE":
        return "Partial result for this image (time budget ended)"
    if summary.production_ready:
        return "This image passes the production-readiness policy"
    if summary.blockers:
        return "This image does not pass the production-readiness policy"
    return "This image was measured; it is not evaluated as production ready"


def _headline(
    summary: DecisionSummary,
    *,
    baseline_met: bool | None = None,
    result: AnalysisResult | None = None,
) -> str:
    if summary.kind is Kind.RECOMMENDED:
        return "Recommended image"
    if summary.kind is Kind.NONE:
        return "No image could be recommended"
    qualifiers: list[str] = []
    if summary.completeness != "COMPLETE":
        qualifiers.append("partial run: time budget ended")
    elif result is not None and result.deferred_count:
        qualifiers.append(f"{result.deferred_count} discovered tags were not measured")
    if result is not None and result.filters_note:
        qualifiers.append("filters applied")
    if baseline_met is False:
        qualifiers.append("none meets the baseline")
    elif summary.blockers:
        qualifiers.append("has readiness blockers")
    suffix = f" ({'; '.join(qualifiers)})" if qualifiers else ""
    return f"Best among the candidates measured{suffix}"
