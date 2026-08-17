"""Confidence is the gate that keeps a technical failure from reading as safety.

The rule under test throughout: a scan that did not complete produces
UNVERIFIED, and nothing -- not a resolved digest, not a registry
confirmation, not a perfect hardening result -- can lift it out of that.
"""

from __future__ import annotations

import itertools

import pytest

from dockerls.domain.value_objects.confidence import (
    CONFIDENCE_ORDER,
    Confidence,
    ConfidenceAssessment,
    ConfidenceInputs,
    confidence_rank,
)
from dockerls.domain.value_objects.tristate import Tristate


class TestTristate:
    def test_none_lifts_to_unknown(self):
        assert Tristate.of(None) is Tristate.UNKNOWN
        assert Tristate.of(True) is Tristate.TRUE
        assert Tristate.of(False) is Tristate.FALSE

    def test_unknown_is_neither_true_nor_false(self):
        assert Tristate.UNKNOWN.is_known is False
        assert Tristate.UNKNOWN.is_true is False
        assert Tristate.UNKNOWN.is_false is False

    def test_unknown_is_falsy_under_is_true_not_under_bool(self):
        """`if facts.has_shell:` is a bug; the tests pin the safe accessors.

        A StrEnum member is truthy, so any code branching on the raw value
        would treat UNKNOWN as "yes". Only `.is_true`/`.is_false` answer.
        """
        assert bool(Tristate.UNKNOWN) is True
        assert Tristate.UNKNOWN.is_true is False


class TestUnverifiedIsAFloor:
    @pytest.mark.parametrize(
        ("cross", "digest", "registry"),
        list(itertools.product([True, False], [True, False], [True, False, None])),
    )
    def test_no_scan_is_always_unverified(self, cross, digest, registry):
        assessment = ConfidenceAssessment(
            ConfidenceInputs(
                scan_verified=False,
                cross_validated=cross,
                digest_resolved=digest,
                registry_verified=registry,
                hardening_coverage=1.0,
            )
        )
        assert assessment.level is Confidence.UNVERIFIED
        assert assessment.reasons

    def test_unverified_is_never_recommendable(self):
        assert Confidence.UNVERIFIED.is_recommendable is False
        for level in (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH):
            assert level.is_recommendable is True


class TestConfidenceLevels:
    def test_full_evidence_is_high(self):
        assessment = ConfidenceAssessment(
            ConfidenceInputs(
                scan_verified=True,
                cross_validated=True,
                digest_resolved=True,
                registry_verified=True,
                hardening_coverage=0.8,
            )
        )
        assert assessment.level is Confidence.HIGH

    def test_scanner_disagreement_drops_to_low(self):
        assessment = ConfidenceAssessment(
            ConfidenceInputs(
                scan_verified=True,
                cross_validated=True,
                scanners_disagree=True,
                digest_resolved=True,
                registry_verified=True,
                hardening_coverage=1.0,
            )
        )
        assert assessment.level is Confidence.LOW
        assert any("disagreed" in reason for reason in assessment.reasons)

    def test_a_refuted_tag_is_low_however_good_everything_else_is(self):
        assessment = ConfidenceAssessment(
            ConfidenceInputs(
                scan_verified=True,
                cross_validated=True,
                digest_resolved=True,
                registry_verified=False,
                hardening_coverage=1.0,
            )
        )
        assert assessment.level is Confidence.LOW

    def test_single_scanner_is_medium_not_high(self):
        assessment = ConfidenceAssessment(
            ConfidenceInputs(
                scan_verified=True,
                cross_validated=False,
                digest_resolved=True,
                registry_verified=True,
                hardening_coverage=0.9,
            )
        )
        assert assessment.level is Confidence.MEDIUM
        assert "only one scanner ran" in assessment.reasons

    def test_thin_hardening_coverage_caps_at_medium(self):
        assessment = ConfidenceAssessment(
            ConfidenceInputs(
                scan_verified=True,
                cross_validated=True,
                digest_resolved=True,
                registry_verified=True,
                hardening_coverage=0.05,
            )
        )
        assert assessment.level is Confidence.MEDIUM

    def test_unpinned_and_unconfirmed_is_low(self):
        assessment = ConfidenceAssessment(
            ConfidenceInputs(scan_verified=True, digest_resolved=False, registry_verified=None)
        )
        assert assessment.level is Confidence.LOW

    def test_ranking_is_monotonic(self):
        ranks = [confidence_rank(level) for level in CONFIDENCE_ORDER]
        assert ranks == sorted(ranks)
        assert confidence_rank(Confidence.UNVERIFIED) < confidence_rank(Confidence.HIGH)
