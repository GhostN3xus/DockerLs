"""The rules the hardening and attack-surface models must hold for every input.

The single property everything else rests on: **an undetermined fact never
moves a score**. Getting that wrong is not a rounding error -- it turns "we
could not look inside this image" into "this image has no shell", which is a
hardening claim nobody made.
"""

from __future__ import annotations

import itertools

import pytest

from dockerls.domain.entities.image_facts import EvidenceSource, HardeningFacts
from dockerls.domain.value_objects.attack_surface import AttackSurfaceScore
from dockerls.domain.value_objects.hardening import (
    MIN_REPORTABLE_COVERAGE,
    MINIMAL_PACKAGE_COUNT,
    NON_ROOT_WEIGHT,
    TOTAL_WEIGHT,
    HardeningScore,
)
from dockerls.domain.value_objects.tristate import Tristate

_STATES = (Tristate.TRUE, Tristate.FALSE, Tristate.UNKNOWN)


def _facts(**kwargs) -> HardeningFacts:
    return HardeningFacts(**kwargs)


def _fully_hardened() -> HardeningFacts:
    return HardeningFacts(
        runs_as_non_root=Tristate.TRUE,
        user="nonroot",
        has_shell=Tristate.FALSE,
        has_package_manager=Tristate.FALSE,
        has_debug_tools=Tristate.FALSE,
        has_setuid=Tristate.FALSE,
        has_healthcheck=Tristate.TRUE,
        package_count=12,
        entrypoint=["/app/server"],
        exposed_ports=[8080],
        config_verified=True,
        evidence={"runs_as_non_root": EvidenceSource.REGISTRY},
    )


class TestUnknownNeverScores:
    def test_nothing_determined_is_not_reportable(self):
        score = HardeningScore(HardeningFacts())
        assert score.coverage == 0.0
        assert score.is_reportable is False
        assert score.undetermined  # every factor is named, none is hidden

    def test_unknown_facts_are_excluded_from_the_denominator(self):
        """A single known-good fact scores 100 -- at a coverage that says so.

        This is the design: the number describes what was checked, and
        `coverage`/`reportable` carry the fact that little was.
        """
        score = HardeningScore(_facts(runs_as_non_root=Tristate.TRUE, user="app"))
        assert score.value == 100.0
        assert score.coverage == pytest.approx(NON_ROOT_WEIGHT / TOTAL_WEIGHT, abs=0.001)

    def test_unknown_is_not_treated_as_absent(self):
        """`has_shell=UNKNOWN` must not earn the "no shell" credit."""
        unknown = HardeningScore(_facts(has_shell=Tristate.UNKNOWN))
        absent = HardeningScore(_facts(has_shell=Tristate.FALSE))
        assert unknown.coverage == 0.0
        assert absent.coverage > 0.0
        assert "no shell present" in absent.strengths

    @pytest.mark.parametrize(
        ("shell", "manager", "debug"), list(itertools.product(_STATES, _STATES, _STATES))
    )
    def test_coverage_only_ever_counts_known_facts(self, shell, manager, debug):
        facts = _facts(has_shell=shell, has_package_manager=manager, has_debug_tools=debug)
        known = sum(1 for state in (shell, manager, debug) if state.is_known)
        score = HardeningScore(facts)
        assert len(score.undetermined) == 9 - known
        assert 0.0 <= score.value <= 100.0


class TestHardeningScoring:
    def test_a_fully_hardened_image_scores_full_marks(self):
        score = HardeningScore(_fully_hardened())
        assert score.value == 100.0
        assert score.is_reportable
        assert score.weaknesses == []

    def test_root_with_a_shell_and_a_package_manager_scores_zero(self):
        score = HardeningScore(
            _facts(
                runs_as_non_root=Tristate.FALSE,
                has_shell=Tristate.TRUE,
                has_package_manager=Tristate.TRUE,
                has_debug_tools=Tristate.TRUE,
                has_setuid=Tristate.TRUE,
            )
        )
        assert score.value == 0.0
        assert "runs as root by default" in score.weaknesses

    def test_privileged_ports_only_count_when_the_config_was_read(self):
        """An empty port list is only a fact if something actually looked."""
        unread = HardeningScore(_facts(exposed_ports=[]))
        read = HardeningScore(_facts(exposed_ports=[], config_verified=True))
        assert "no-privileged-ports" in unread.undetermined
        assert "exposes no privileged ports" in read.strengths

    def test_privileged_port_is_a_named_weakness(self):
        score = HardeningScore(_facts(exposed_ports=[80, 8080], config_verified=True))
        assert any("privileged port(s) 80" in w for w in score.weaknesses)

    def test_package_count_tapers_rather_than_cliff_edging(self):
        minimal = HardeningScore(_facts(package_count=MINIMAL_PACKAGE_COUNT))
        just_over = HardeningScore(_facts(package_count=MINIMAL_PACKAGE_COUNT + 1))
        many = HardeningScore(_facts(package_count=MINIMAL_PACKAGE_COUNT * 4))
        assert minimal.value == 100.0
        assert 0.0 < just_over.value < 100.0
        assert many.value == 0.0

    def test_a_shell_entrypoint_earns_no_entrypoint_credit(self):
        shell = HardeningScore(_facts(entrypoint=["/bin/sh", "-c"], config_verified=True))
        binary = HardeningScore(_facts(entrypoint=["/app/server"], config_verified=True))
        assert any("entrypoint is a shell" in w for w in shell.weaknesses)
        assert any("entrypoint /app/server" in s for s in binary.strengths)

    def test_reportability_threshold_is_honoured(self):
        thin = HardeningScore(_facts(has_healthcheck=Tristate.TRUE))
        assert thin.coverage < MIN_REPORTABLE_COVERAGE
        assert thin.is_reportable is False

    def test_score_is_deterministic(self):
        facts = _fully_hardened()
        assert HardeningScore(facts).value == HardeningScore(facts).value


class TestAttackSurface:
    def test_higher_means_more_surface(self):
        loaded = AttackSurfaceScore(
            _facts(
                has_shell=Tristate.TRUE,
                has_package_manager=Tristate.TRUE,
                has_debug_tools=Tristate.TRUE,
                has_setuid=Tristate.TRUE,
                runs_as_non_root=Tristate.FALSE,
                package_count=800,
            )
        )
        clean = AttackSurfaceScore(_fully_hardened())
        assert loaded.value == 100.0
        assert clean.value < 10.0
        assert loaded.value > clean.value

    def test_size_alone_does_not_create_surface(self):
        """A huge image with nothing installed is not a large attack surface."""
        big = AttackSurfaceScore(_facts(size_bytes=900 * 1024 * 1024, package_count=3))
        small = AttackSurfaceScore(_facts(size_bytes=5 * 1024 * 1024, package_count=350))
        assert big.value < small.value

    def test_unknown_contributes_nothing(self):
        score = AttackSurfaceScore(HardeningFacts())
        assert score.value == 0.0
        assert score.is_reportable is False
        assert score.present == []
        assert score.absent == []

    def test_absent_items_are_reported_as_findings(self):
        score = AttackSurfaceScore(_facts(has_package_manager=Tristate.FALSE))
        assert "no package manager" in score.absent
        assert score.present == []
