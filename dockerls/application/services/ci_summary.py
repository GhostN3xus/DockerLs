"""A short, versioned, machine-readable verdict for pipelines.

`--format json` is the complete result; a pipeline step usually wants four
things from it, in a shape that will not change under it: *did it pass*, *what
blocks it*, *is that the whole story*, and *exactly which bytes was it about*.
This is that, with a `schema` a consumer can pin and refuse to guess about.

`status` is deliberately not a boolean:

* `PASS` -- complete, measured, no blockers, nothing pending;
* `PASS_WITH_PENDING_CHECKS` -- no blockers, but a check did not run (a
  profile skipped it, the budget cut it, a source was down): the pass does not
  extend to what was not checked, and the list says what that is;
* `FAIL` -- measured, and the policy or a gate failed;
* `INCOMPLETE` -- the run ended (time budget) before it could say;
* `ERROR` -- nothing could be measured (a tool, database or registry failed).

`exit_code` is the process exit code of the same run, so the document and the
shell agree; the codes are the documented, deterministic ones.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from dockerls import __version__
from dockerls.application.services.decision_summary import DecisionSummary, Kind

CI_SCHEMA = "dockerls.ci-summary/1"


class CiSummary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    schema_id: str = Field(default=CI_SCHEMA, alias="schema")
    tool_version: str = __version__
    generated_at: str = ""
    command: str = ""
    run_id: str = ""
    status: str = "ERROR"
    exit_code: int = 1
    completeness: str = "COMPLETE"
    blockers: list[str] = Field(default_factory=list)
    problems: list[str] = Field(default_factory=list)
    pending_checks: list[str] = Field(default_factory=list)
    image: dict[str, Any] = Field(default_factory=dict)
    findings: dict[str, int | None] = Field(default_factory=dict)
    confidence: str = "UNKNOWN"
    provenance: dict[str, Any] = Field(default_factory=dict)
    freshness: dict[str, Any] = Field(default_factory=dict)
    policy: dict[str, Any] = Field(default_factory=dict)


def _status(summary: DecisionSummary, exit_code: int) -> str:
    if summary.kind is Kind.NONE:
        infrastructure = any(p.startswith("INFRASTRUCTURE") for p in summary.problems)
        if summary.completeness != "COMPLETE":
            return "INCOMPLETE"
        return "ERROR" if infrastructure or exit_code == 1 else "FAIL"
    if summary.completeness != "COMPLETE":
        return "INCOMPLETE"
    if summary.blockers or any(p.startswith("POLICY") for p in summary.problems) or exit_code:
        return "FAIL"
    return "PASS_WITH_PENDING_CHECKS" if summary.pending_checks else "PASS"


def build_ci_summary(
    summary: DecisionSummary,
    *,
    command: str,
    exit_code: int,
    run_id: str = "",
    baseline: dict[str, int] | None = None,
    now: datetime | None = None,
) -> CiSummary:
    return CiSummary(
        generated_at=(now or datetime.now(tz=UTC)).isoformat(),
        command=command,
        run_id=run_id,
        status=_status(summary, exit_code),
        exit_code=exit_code,
        completeness=summary.completeness,
        blockers=list(summary.blockers),
        problems=list(summary.problems),
        pending_checks=list(summary.pending_checks),
        image={
            "requested": summary.requested_reference,
            "resolved": summary.pinned_reference,
            "measured": summary.measured_reference,
            "platform": summary.platform,
            "index_digest": summary.index_digest,
            "identity_status": summary.identity_status,
            "identity_confirmed": summary.identity_status == "CONFIRMED",
        },
        findings={
            "critical": summary.critical,
            "high": summary.high,
            "medium": summary.medium,
            "low": summary.low,
            "fixable": summary.fixable,
            "total": summary.total,
        },
        confidence=summary.confidence,
        provenance={
            "origin": summary.origin,
            "scanner": summary.scanner,
            "scanner_version": summary.scanner_version,
            "database_revision": summary.db_revision or None,
            "measured_at": summary.measured_at or None,
        },
        freshness={
            "measurement_age_seconds": summary.measurement_age_seconds,
            "database_age_seconds": summary.db_age_seconds,
        },
        policy={"production_ready": summary.production_ready, **(baseline or {})},
    )
