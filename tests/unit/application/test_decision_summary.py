"""The decision summary: what to use, pinned to what, and how far to trust it."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from dockerls.application.dto.analysis import (
    AnalysisResult,
    ImageAnalysis,
    MeasurementProvenance,
    UnverifiedImage,
)
from dockerls.application.services.decision_summary import (
    Category,
    Kind,
    age_seconds,
    humanize_age,
    summarize_analysis,
    summarize_recommendation,
)
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.value_objects.confidence import Confidence

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
DIGEST = "sha256:" + "a" * 64


def _analysis(*, confirmed=True, criticals=0, ready=True, blockers=None, divergence="", **prov):
    scan = ScanResult(
        image_reference=f"node@{DIGEST}",
        scan_timestamp=(NOW - timedelta(minutes=5)).isoformat(),
        vulnerabilities=[
            Vulnerability(cve_id=f"CVE-2026-{i}", severity=Severity.CRITICAL, fixed_version="1")
            for i in range(criticals)
        ]
        + [Vulnerability(cve_id="CVE-2026-9", severity=Severity.HIGH)],
    )
    image = DockerImage(
        name="node",
        tag="22-alpine",
        digest=DIGEST if confirmed else "",
        platform="linux/amd64",
        identity_status="CONFIRMED" if confirmed else "UNRESOLVED",
        identity_limitation="" if confirmed else "registry offline",
    )
    provenance = MeasurementProvenance(
        origin=prov.get("origin", "scan"),
        measured_at=(NOW - timedelta(minutes=5)).isoformat(),
        db_revision=prov.get("db_revision", (NOW - timedelta(hours=5)).isoformat()),
        scanner="trivy",
        scanner_version="trivy 0.60",
        requested_reference="node:22-alpine",
        resolved_reference=f"node@{DIGEST}" if confirmed else "",
        measured_reference=f"node@{DIGEST}" if confirmed else "node:22-alpine",
    )
    return ImageAnalysis(
        image=image,
        scan=scan,
        security_score=91.0,
        tier="B",
        remediation_score=80,
        production_ready=ready,
        readiness_blockers=blockers or [],
        readiness_reasons=["x" for _ in blockers or []],
        confidence=Confidence.MEDIUM,
        why=["fewest CRITICAL findings among the measured candidates"],
        provenance=provenance,
        scan_divergence=divergence,
    )


def _result(*analyses, baseline_met=True, **kwargs):
    return AnalysisResult(
        query="node",
        total_tags_scanned=len(analyses),
        total_tags_analyzed=len(analyses),
        baseline_met=baseline_met,
        recommendations=list(analyses) if baseline_met else [],
        alternatives=[] if baseline_met else list(analyses),
        **kwargs,
    )


class TestWording:
    def test_a_complete_passing_result_is_a_recommendation(self):
        summary = summarize_recommendation(_result(_analysis()), now=NOW)

        assert summary.kind is Kind.RECOMMENDED
        assert summary.headline == "Recommended image"
        assert summary.problems == []

    def test_below_the_baseline_it_is_the_best_of_the_measured_never_the_best(self):
        summary = summarize_recommendation(
            _result(_analysis(criticals=2), baseline_met=False), now=NOW
        )

        assert summary.kind is Kind.BEST_MEASURED
        assert summary.headline.startswith("Best among the candidates measured")
        assert "none meets the baseline" in summary.headline
        assert "recommended" not in summary.headline.lower()

    def test_a_partial_run_says_so_in_the_headline(self):
        summary = summarize_recommendation(
            _result(_analysis(), completeness="PARTIAL", pending_checks=["x"]), now=NOW
        )
        assert summary.kind is Kind.BEST_MEASURED
        assert "partial run" in summary.headline
        assert "partial" in summary.next_action.lower()

    def test_filters_that_removed_candidates_turn_the_recommendation_into_best_measured(self):
        summary = summarize_recommendation(
            _result(_analysis(), filters_note="2 of 9 excluded"), now=NOW
        )
        assert summary.kind is Kind.BEST_MEASURED
        assert "filters applied" in summary.headline

    def test_nothing_measured_is_none(self):
        result = AnalysisResult(query="node", total_tags_scanned=0, baseline_met=False)
        summary = summarize_recommendation(result, now=NOW)
        assert summary.kind is Kind.NONE
        assert summary.image == ""


class TestIdentity:
    def test_a_confirmed_identity_is_pinned_and_platform_stated(self):
        summary = summarize_recommendation(_result(_analysis()), now=NOW)
        assert summary.pinned_reference == f"node@{DIGEST}"
        assert summary.platform == "linux/amd64"
        assert summary.requested_reference == "node:22-alpine"
        assert summary.measured_reference == f"node@{DIGEST}"

    def test_an_unconfirmed_identity_offers_no_pin_and_says_why(self):
        summary = summarize_recommendation(_result(_analysis(confirmed=False)), now=NOW)
        assert summary.pinned_reference == ""
        assert "registry offline" in summary.identity_note
        assert "not confirmed" not in summary.identity_note, "the renderer adds the verdict"
        assert "identity could not be pinned" in summary.next_action


class TestNoBlockerIsHiddenByAScore:
    def test_blockers_travel_with_the_score(self):
        analysis = _analysis(ready=False, blockers=["CRITICAL_FINDINGS", "END_OF_LIFE"])
        summary = summarize_recommendation(_result(analysis), now=NOW)

        assert summary.score == 91.0
        assert summary.blockers == ["CRITICAL_FINDINGS", "END_OF_LIFE"]
        assert any(p.startswith("POLICY") and "CRITICAL_FINDINGS" in p for p in summary.problems)
        assert "CRITICAL_FINDINGS" in summary.next_action

    def test_a_score_two_scanners_dispute_is_not_shown_as_a_number(self):
        summary = summarize_recommendation(
            _result(_analysis(divergence="HIGH trivy=0 vs grype=9")), now=NOW
        )
        assert summary.score is None
        assert "trivy=0" in summary.score_disputed


class TestThreeKindsOfNotOk:
    def test_policy_incomplete_and_infrastructure_are_kept_apart(self):
        result = _result(
            _analysis(ready=False, blockers=["HIGH_FINDINGS"]),
            pending_checks=["cross-validation with a second scanner (not run)"],
            unverified=[
                UnverifiedImage(
                    image_reference="node:1", status="ERROR", reason="x", kind="DB_INIT_FAILED"
                )
            ],
        )

        summary = summarize_recommendation(result, now=NOW)

        assert set(summary.categories) == {
            Category.POLICY,
            Category.INCOMPLETE,
            Category.INFRASTRUCTURE,
        }
        prefixes = {p.split(":")[0] for p in summary.problems}
        assert prefixes == {"POLICY", "INCOMPLETE", "INFRASTRUCTURE"}

    def test_a_missing_tag_is_a_fact_about_the_image_not_an_infrastructure_failure(self):
        result = _result(
            _analysis(),
            unverified=[
                UnverifiedImage(
                    image_reference="node:9", status="TAG_NOT_FOUND", reason="", kind="NOT_FOUND"
                )
            ],
        )
        summary = summarize_recommendation(result, now=NOW)
        assert Category.INFRASTRUCTURE not in summary.categories

    def test_infrastructure_failure_drives_the_next_action(self):
        result = AnalysisResult(
            query="node",
            total_tags_scanned=3,
            baseline_met=False,
            unverified=[
                UnverifiedImage(
                    image_reference=f"node:{i}", status="ERROR", reason="x", kind="SCANNER_MISSING"
                )
                for i in range(3)
            ],
        )
        summary = summarize_recommendation(result, now=NOW)
        assert summary.kind is Kind.NONE
        assert "Install Trivy or Grype" in summary.next_action


class TestUnknownStaysUnknown:
    def test_an_unknown_database_age_is_reported_as_missing_not_as_fresh(self):
        summary = summarize_recommendation(_result(_analysis(db_revision="")), now=NOW)

        assert summary.db_age_seconds is None
        assert any("vulnerability database could not be determined" in p for p in summary.problems)

    @pytest.mark.parametrize(
        ("seconds", "text"),
        [
            (None, "unknown"),
            (30, "30 seconds"),
            (600, "10 minutes"),
            (7200, "2 hours"),
            (3 * 86400, "3.0 days"),
        ],
    )
    def test_ages_read_naturally_and_unknown_is_a_word(self, seconds, text):
        assert humanize_age(seconds) == text

    def test_an_unreadable_timestamp_has_no_age(self):
        assert age_seconds("yesterday-ish", NOW) is None
        assert age_seconds("", NOW) is None

    def test_a_timestamp_in_the_future_never_yields_a_negative_age(self):
        assert age_seconds((NOW + timedelta(hours=1)).isoformat(), NOW) == 0.0


class TestProvenance:
    @pytest.mark.parametrize("origin", ["scan", "cache", "shared"])
    def test_the_origin_of_the_result_is_carried(self, origin):
        summary = summarize_recommendation(_result(_analysis(origin=origin)), now=NOW)
        assert summary.origin == origin

    def test_measurement_and_database_ages_are_computed(self):
        summary = summarize_recommendation(_result(_analysis()), now=NOW)
        assert summary.measurement_age_seconds == 300
        assert summary.db_age_seconds == 5 * 3600


def test_analyze_summary_uses_the_same_rules():
    summary = summarize_analysis(_analysis(ready=False, blockers=["TIER_TOO_LOW"]), now=NOW)
    assert summary.kind is Kind.BEST_MEASURED
    assert summary.blockers == ["TIER_TOO_LOW"]
