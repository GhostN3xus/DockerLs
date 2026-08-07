from dockerls.domain.entities.build_validation import (
    CheckStatus,
    ValidationCheck,
    ValidationResult,
)
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.value_objects.build_score import BuildScore, BuildTier


def _validation(*checks):
    return ValidationResult(checks=list(checks))


def _check(status, severity=Severity.MEDIUM, name="rule"):
    return ValidationCheck(check=name, status=status, severity=severity)


def _clean():
    return _validation(_check(CheckStatus.PASS))


def _scan(**counts):
    vulns = [
        Vulnerability(cve_id=f"CVE-{severity}-{i}", severity=Severity(severity.upper()))
        for severity, n in counts.items()
        for i in range(n)
    ]
    return ScanResult(image_reference="app:1.0", vulnerabilities=vulns, scan_timestamp="now")


class TestDockerfileOnlyScoring:
    def test_all_checks_passing_is_100(self):
        assert BuildScore(_clean()).value == 100.0

    def test_scan_score_is_none_without_a_scan(self):
        """Deliberately not 0 and not 100: a report must be able to say
        "not measured" rather than imply a measurement."""
        assert BuildScore(_clean()).scan_score is None

    def test_a_critical_finding_costs_more_than_a_low_one(self):
        critical = BuildScore(_validation(_check(CheckStatus.FAIL, Severity.CRITICAL))).value
        low = BuildScore(_validation(_check(CheckStatus.WARN, Severity.LOW))).value
        assert critical < low < 100.0

    def test_skipped_checks_neither_help_nor_hurt(self):
        with_skip = _validation(_check(CheckStatus.PASS), _check(CheckStatus.SKIP, name="other"))
        assert BuildScore(with_skip).value == BuildScore(_clean()).value

    def test_score_is_clamped_at_zero(self):
        many = _validation(
            *[_check(CheckStatus.FAIL, Severity.CRITICAL, f"r{i}") for i in range(9)]
        )
        assert BuildScore(many).value == 0.0


class TestCombinedScoring:
    def test_a_clean_scan_and_clean_dockerfile_is_100(self):
        assert BuildScore(_clean(), _scan()).value == 100.0

    def test_the_scan_weighs_more_than_the_dockerfile(self):
        """A shipped CVE is a fact about the artefact; a validation finding
        is a fact about how it was written. The artefact wins."""
        bad_scan = BuildScore(_clean(), _scan(high=4)).value
        bad_file = BuildScore(_validation(_check(CheckStatus.WARN, Severity.MEDIUM)), _scan()).value
        assert bad_scan < bad_file

    def test_a_perfect_dockerfile_cannot_hide_a_vulnerable_image(self):
        score = BuildScore(_clean(), _scan(critical=2))
        assert score.value <= 70
        assert score.tier is BuildTier.C
        assert not score.production_ready

    def test_a_clean_image_cannot_excuse_a_leaked_credential(self):
        leaked = _validation(_check(CheckStatus.FAIL, Severity.CRITICAL, "secrets_not_in_env"))
        score = BuildScore(leaked, _scan())
        assert score.tier in (BuildTier.B, BuildTier.C)
        assert not score.production_ready


class TestTiers:
    def test_any_critical_caps_the_tier_at_c(self):
        """Arithmetic must never present a knowingly-vulnerable image as
        production-ready, however good the weighted average looks."""
        assert BuildScore(_clean(), _scan(critical=1)).tier is BuildTier.C

    def test_more_than_three_highs_caps_the_tier_at_c(self):
        assert BuildScore(_clean(), _scan(high=4)).tier is BuildTier.C

    def test_a_few_mediums_stay_production_ready(self):
        score = BuildScore(_clean(), _scan(medium=2, low=5))
        assert score.tier in (BuildTier.S, BuildTier.A)
        assert score.production_ready

    def test_a_hard_validation_failure_caps_the_tier_at_b(self):
        failing = _validation(_check(CheckStatus.FAIL, Severity.HIGH))
        assert BuildScore(failing, _scan()).tier is BuildTier.B

    def test_every_tier_carries_advice(self):
        for scan, expected_ready in [(_scan(), True), (_scan(critical=1), False)]:
            score = BuildScore(_clean(), scan)
            assert score.advice
            assert score.production_ready is expected_ready
