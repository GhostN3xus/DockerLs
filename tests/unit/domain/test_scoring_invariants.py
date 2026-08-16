"""Properties the score must hold for *every* input, not just the examples.

`test_value_objects.py` checks the score on hand-picked cases. These check
the rules those cases are supposed to be instances of, swept exhaustively
across the severity space, so a future change to a penalty constant cannot
quietly break an ordering guarantee that no single example happened to
cover.

The rules, stated once:

1. The score never leaves [0, 100].
2. Adding a vulnerability never *raises* the score.
3. Removing a vulnerability never *lowers* it.
4. Severity is ordered: a CRITICAL costs at least as much as a HIGH, which
   costs at least as much as a MEDIUM.
5. An EOL image is never production-ready, at any tier.
6. A CRITICAL with no fix available caps the tier at C, from any score.
7. Every score in [0, 100] maps to exactly one tier.
"""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta

import pytest

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.value_objects.security_score import SecurityScore
from dockerls.domain.value_objects.security_tier import (
    PRODUCTION_READY_TIERS,
    TIER_ORDER,
    SecurityTier,
    Tier,
    tier_for_score,
)

_SEVERITIES = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


def _vuln(severity: Severity, index: int = 0, *, fixable: bool = True) -> Vulnerability:
    return Vulnerability(
        cve_id=f"CVE-2024-{1000 + index}",
        severity=severity,
        package_name="openssl",
        installed_version="1.0",
        fixed_version="1.1" if fixable else "",
    )


def _vulns(critical: int = 0, high: int = 0, medium: int = 0, low: int = 0, *, fixable=True):
    out: list[Vulnerability] = []
    for severity, count in (
        (Severity.CRITICAL, critical),
        (Severity.HIGH, high),
        (Severity.MEDIUM, medium),
        (Severity.LOW, low),
    ):
        out.extend(_vuln(severity, len(out) + i, fixable=fixable) for i in range(count))
    return out


def _image(**kwargs) -> DockerImage:
    defaults = {
        "name": "node",
        "tag": "22-alpine",
        "is_official": True,
        "last_updated": datetime.now(tz=UTC) - timedelta(days=5),
    }
    defaults.update(kwargs)
    return DockerImage(**defaults)


def _score(vulns, image=None, **kwargs) -> float:
    image = image or _image()
    scan = ScanResult(image_reference=image.full_reference, vulnerabilities=vulns)
    return SecurityScore(image, scan, **kwargs).value


# A grid wide enough to cross both the clamp at 0 and the clamp at 100.
_COUNTS = (0, 1, 2, 5, 12)


class TestScoreStaysInRange:
    @pytest.mark.parametrize(("crit", "high", "med"), list(itertools.product(_COUNTS, repeat=3)))
    def test_bounded_for_every_severity_mix(self, crit, high, med):
        assert 0.0 <= _score(_vulns(crit, high, med)) <= 100.0

    @pytest.mark.parametrize("eol", [True, False])
    @pytest.mark.parametrize("lts", [True, False])
    def test_bounded_with_eol_and_lts_applied(self, eol, lts):
        assert 0.0 <= _score(_vulns(3, 3, 3), is_eol=eol, is_lts=lts) <= 100.0

    def test_an_overwhelming_scan_floors_at_zero_rather_than_going_negative(self):
        assert _score(_vulns(critical=200)) == 0.0

    def test_a_perfectly_decorated_clean_image_reaches_but_never_passes_100(self):
        image = _image(
            name="cgr.dev/chainguard/node",
            tag="latest",
            is_official=True,
            is_signed=True,
            last_updated=datetime.now(tz=UTC),
        )
        assert _score([], image=image, is_lts=True) == 100.0


class TestMonotonicity:
    """Adding a finding may only ever cost. This is the property a security
    tool cannot get wrong: a score that improves when a vulnerability is
    discovered would invert the ranking it exists to produce."""

    @pytest.mark.parametrize("severity", _SEVERITIES)
    @pytest.mark.parametrize(("crit", "high", "med"), list(itertools.product((0, 1, 3), repeat=3)))
    def test_adding_a_vulnerability_never_raises_the_score(self, severity, crit, high, med):
        base = _vulns(crit, high, med)
        before = _score(base)
        after = _score([*base, _vuln(severity, len(base))])
        assert after <= before

    @pytest.mark.parametrize("severity", _SEVERITIES)
    def test_removing_a_vulnerability_never_lowers_the_score(self, severity):
        with_it = [*_vulns(1, 1, 1), _vuln(severity, 9)]
        without = _vulns(1, 1, 1)
        assert _score(without) >= _score(with_it)

    @pytest.mark.parametrize("count", range(1, 8))
    def test_the_score_is_non_increasing_as_criticals_accumulate(self, count):
        assert _score(_vulns(critical=count)) <= _score(_vulns(critical=count - 1))

    def test_the_sequence_is_monotone_end_to_end(self):
        scores = [_score(_vulns(high=n)) for n in range(0, 25)]
        assert scores == sorted(scores, reverse=True)


class TestSeverityIsOrdered:
    @pytest.mark.parametrize("count", [1, 2, 5])
    def test_a_critical_costs_at_least_as_much_as_a_high(self, count):
        assert _score(_vulns(critical=count)) <= _score(_vulns(high=count))

    @pytest.mark.parametrize("count", [1, 2, 5])
    def test_a_high_costs_at_least_as_much_as_a_medium(self, count):
        assert _score(_vulns(high=count)) <= _score(_vulns(medium=count))

    def test_severity_beats_count(self):
        """One CRITICAL must outrank a pile of MEDIUMs of the same nominal
        weight -- otherwise the baseline could be met by an image that is
        one exploit away from compromise."""
        assert _score(_vulns(critical=1)) < _score(_vulns(medium=15))


class TestEolIsNeverProductionReady:
    @pytest.mark.parametrize("tier", list(Tier))
    def test_no_tier_makes_an_eol_image_deployable(self, tier):
        scan = ScanResult(image_reference="node:22", vulnerabilities=[])
        floor = {Tier.A: 95.0, Tier.B: 80.0, Tier.C: 65.0, Tier.D: 45.0, Tier.E: 25.0, Tier.F: 5.0}
        assert SecurityTier(scan, floor[tier], is_eol=True).production_ready is False

    def test_a_flawless_eol_image_is_still_not_production_ready(self):
        image = _image()
        scan = ScanResult(image_reference=image.full_reference, vulnerabilities=[])
        score = SecurityScore(image, scan, is_eol=True).value
        assert SecurityTier(scan, score, is_eol=True).production_ready is False

    def test_eol_always_costs_score(self):
        assert _score([], is_eol=True) < _score([], is_eol=False)


class TestUnfixableCriticalCeiling:
    @pytest.mark.parametrize("score", [100.0, 95.0, 90.0, 80.0, 60.0])
    def test_no_score_lifts_an_unfixable_critical_above_c(self, score):
        scan = ScanResult(
            image_reference="node:22", vulnerabilities=_vulns(critical=1, fixable=False)
        )
        tier = SecurityTier(scan, score).tier
        assert TIER_ORDER.index(tier) >= TIER_ORDER.index(Tier.C)
        assert tier not in PRODUCTION_READY_TIERS

    @pytest.mark.parametrize("score", [30.0, 10.0, 0.0])
    def test_the_ceiling_never_promotes_a_worse_tier(self, score):
        """It is a cap, not a floor: an image scoring 0 must not be lifted
        to C because it happens to carry an unfixable critical."""
        clean = ScanResult(image_reference="node:22", vulnerabilities=[])
        unfixable = ScanResult(
            image_reference="node:22", vulnerabilities=_vulns(critical=1, fixable=False)
        )
        assert TIER_ORDER.index(SecurityTier(unfixable, score).tier) >= TIER_ORDER.index(
            SecurityTier(clean, score).tier
        )

    def test_a_fixable_critical_is_not_capped(self):
        scan = ScanResult(
            image_reference="node:22", vulnerabilities=_vulns(critical=1, fixable=True)
        )
        assert SecurityTier(scan, 95.0).tier is Tier.A


class TestTierBandsPartitionTheScale:
    @pytest.mark.parametrize("score", [n / 2 for n in range(0, 201)])
    def test_every_score_maps_to_exactly_one_tier(self, score):
        assert tier_for_score(score) in set(Tier)

    @pytest.mark.parametrize("score", [n / 2 for n in range(0, 201)])
    def test_tiers_never_improve_as_the_score_falls(self, score):
        lower = tier_for_score(max(0.0, score - 0.5))
        assert TIER_ORDER.index(lower) >= TIER_ORDER.index(tier_for_score(score))
