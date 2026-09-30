"""The CI summary: versioned, deterministic, and unable to say "PASS" about
something that was not fully checked or not fully measured."""

from __future__ import annotations

import json

import pytest

from dockerls.application.services.ci_summary import CI_SCHEMA, build_ci_summary
from dockerls.application.services.decision_summary import DecisionSummary, Kind

DIGEST = "sha256:" + "b" * 64


def _summary(**overrides) -> DecisionSummary:
    base = {
        "kind": Kind.RECOMMENDED,
        "requested_reference": "node:22",
        "pinned_reference": f"node@{DIGEST}",
        "measured_reference": f"node@{DIGEST}",
        "platform": "linux/amd64",
        "identity_status": "CONFIRMED",
        "critical": 0,
        "high": 0,
        "medium": 3,
        "low": 1,
        "fixable": 2,
        "total": 4,
        "confidence": "HIGH",
        "production_ready": True,
        "scanner": "trivy",
        "scanner_version": "trivy 0.60",
        "db_revision": "2026-09-30T00:00:00+00:00",
        "measured_at": "2026-09-30T12:00:00+00:00",
        "origin": "scan",
    }
    base.update(overrides)
    return DecisionSummary(**base)


def _ci(summary, code=0):
    return build_ci_summary(
        summary, command="recommend", exit_code=code, run_id="20260930T000000Z-abcd1234"
    )


def test_the_document_is_versioned_and_serialises_with_a_schema_key():
    ci = _ci(_summary())
    payload = json.loads(json.dumps(ci.model_dump(by_alias=True)))

    assert payload["schema"] == CI_SCHEMA == "dockerls.ci-summary/1"
    assert "schema_id" not in payload
    assert payload["run_id"] == "20260930T000000Z-abcd1234"


def test_it_carries_what_a_pipeline_needs_to_pin_a_result():
    payload = _ci(_summary()).model_dump(by_alias=True)

    assert payload["image"]["resolved"] == f"node@{DIGEST}"
    assert payload["image"]["platform"] == "linux/amd64"
    assert payload["image"]["identity_confirmed"] is True
    assert payload["findings"]["critical"] == 0
    assert payload["provenance"]["scanner_version"] == "trivy 0.60"
    assert payload["provenance"]["database_revision"] == "2026-09-30T00:00:00+00:00"
    assert payload["exit_code"] == 0


class TestStatusIsNeverJustABoolean:
    def test_clean_and_complete_is_a_pass(self):
        assert _ci(_summary()).status == "PASS"

    def test_pending_checks_prevent_a_plain_pass(self):
        ci = _ci(_summary(pending_checks=["cross-validation with a second scanner (not run)"]))
        assert ci.status == "PASS_WITH_PENDING_CHECKS"
        assert ci.pending_checks

    def test_blockers_fail(self):
        ci = _ci(_summary(blockers=["CRITICAL_FINDINGS"], production_ready=False), code=1)
        assert ci.status == "FAIL"
        assert ci.blockers == ["CRITICAL_FINDINGS"]

    def test_a_partial_run_is_incomplete_not_pass(self):
        ci = _ci(_summary(completeness="PARTIAL"), code=5)
        assert ci.status == "INCOMPLETE"
        assert ci.completeness == "PARTIAL"

    def test_a_non_zero_exit_code_can_never_be_a_pass(self):
        assert _ci(_summary(), code=2).status == "FAIL"

    def test_nothing_measured_because_of_infrastructure_is_an_error(self):
        ci = _ci(
            _summary(
                kind=Kind.NONE, problems=["INFRASTRUCTURE: scans failed (SCANNER_MISSING x3)"]
            ),
            code=1,
        )
        assert ci.status == "ERROR"

    def test_nothing_measured_because_time_ran_out_is_incomplete(self):
        assert (
            _ci(_summary(kind=Kind.NONE, completeness="NO_RESULT"), code=4).status == "INCOMPLETE"
        )


@pytest.mark.parametrize(
    ("field", "key"),
    [
        ("measurement_age_seconds", "measurement_age_seconds"),
        ("db_age_seconds", "database_age_seconds"),
    ],
)
def test_unknown_ages_are_null_not_zero(field, key):
    freshness = _ci(_summary(**{field: None})).model_dump(by_alias=True)["freshness"]
    assert key in freshness and freshness[key] is None


def test_an_unconfirmed_identity_is_visible_in_the_document():
    ci = _ci(_summary(pinned_reference="", identity_status="UNRESOLVED"))
    assert ci.image["resolved"] == ""
    assert ci.image["identity_confirmed"] is False
