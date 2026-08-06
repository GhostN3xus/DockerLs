from datetime import UTC, datetime, timedelta

import pytest

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.value_objects.remediation_score import RemediationScore
from dockerls.domain.value_objects.security_score import SecurityScore
from dockerls.domain.value_objects.security_tier import SecurityTier, Tier


def _image(**kwargs):
    defaults = {
        "name": "node",
        "tag": "22-alpine",
        "is_official": True,
        "last_updated": datetime.now(tz=UTC) - timedelta(days=5),
    }
    defaults.update(kwargs)
    return DockerImage(**defaults)


def _scan(vulns=None):
    return ScanResult(image_reference="node:22-alpine", vulnerabilities=vulns or [])


class TestSecurityScore:
    def test_perfect_score(self):
        img = _image()
        scan = _scan()
        score = SecurityScore(img, scan)
        assert score.value > 90

    def test_critical_penalty(self):
        scan = _scan([Vulnerability(cve_id="C1", severity=Severity.CRITICAL)])
        score = SecurityScore(_image(), scan)
        assert score.value <= 90

    def test_score_clamped_to_zero(self):
        vulns = [Vulnerability(cve_id=f"C{i}", severity=Severity.CRITICAL) for i in range(10)]
        score = SecurityScore(_image(), _scan(vulns))
        assert score.value == 0.0

    def test_score_clamped_to_hundred(self):
        img = _image(last_updated=datetime.now(tz=UTC))
        score = SecurityScore(img, _scan())
        assert score.value <= 100.0

    def test_eol_penalty(self):
        score_normal = SecurityScore(_image(), _scan())
        score_eol = SecurityScore(_image(), _scan(), is_eol=True)
        assert score_eol.value < score_normal.value

    def test_lts_bonus(self):
        score_normal = SecurityScore(_image(), _scan())
        score_lts = SecurityScore(_image(), _scan(), is_lts=True)
        assert score_lts.value >= score_normal.value

    def test_rejects_error_scan(self):
        scan = ScanResult(
            image_reference="node:22-alpine",
            status=ScanStatus.ERROR,
            error_message="trivy exited 1",
        )
        with pytest.raises(ValueError):
            SecurityScore(_image(), scan)

    def test_rejects_timeout_scan(self):
        scan = ScanResult(image_reference="node:22-alpine", status=ScanStatus.TIMEOUT)
        with pytest.raises(ValueError):
            SecurityScore(_image(), scan)

    def test_accepts_partial_scan(self):
        scan = ScanResult(image_reference="node:22-alpine", status=ScanStatus.PARTIAL)
        score = SecurityScore(_image(), scan)
        assert score.value > 0

    def test_known_exploited_penalty(self):
        clean = SecurityScore(_image(), _scan())
        v = Vulnerability(cve_id="C1", severity=Severity.HIGH, exploit_known=True)
        exploited = SecurityScore(_image(), _scan([v]))
        assert exploited.value < clean.value

    def test_high_epss_penalty(self):
        # Enough HIGH vulns to push the base score well under 100 so the
        # EPSS penalty isn't hidden by the [0, 100] clamp.
        base_vulns = [Vulnerability(cve_id=f"H{i}", severity=Severity.HIGH) for i in range(6)]
        low_vuln = Vulnerability(cve_id="C1", severity=Severity.HIGH, epss_score=0.1)
        high_vuln = Vulnerability(cve_id="C1", severity=Severity.HIGH, epss_score=0.9)
        low_epss = SecurityScore(_image(), _scan([*base_vulns, low_vuln]))
        high_epss = SecurityScore(_image(), _scan([*base_vulns, high_vuln]))
        assert high_epss.value < low_epss.value

    def test_hardened_source_bonus_not_double_counted_with_alpine(self):
        hardened_alpine = _image(name="chainguard/node", tag="22-alpine")
        alpine_only = _image(name="node", tag="22-alpine")
        score_hardened = SecurityScore(hardened_alpine, _scan())
        score_alpine = SecurityScore(alpine_only, _scan())
        # Both get the same +3 "minimal base" bonus, not stacked +6.
        assert score_hardened.value == score_alpine.value


class TestSecurityTier:
    def test_tier_s(self):
        tier = SecurityTier(_scan())
        assert tier.tier == Tier.S
        assert tier.production_ready is True

    def test_tier_a(self):
        vulns = [
            Vulnerability(cve_id="H1", severity=Severity.HIGH, fixed_version="1.0"),
            Vulnerability(cve_id="H2", severity=Severity.HIGH, fixed_version="2.0"),
        ]
        tier = SecurityTier(_scan(vulns))
        assert tier.tier == Tier.A

    def test_tier_b(self):
        vulns = [Vulnerability(cve_id=f"H{i}", severity=Severity.HIGH) for i in range(5)]
        tier = SecurityTier(_scan(vulns))
        assert tier.tier == Tier.B

    def test_tier_c(self):
        vulns = [Vulnerability(cve_id="C1", severity=Severity.CRITICAL)]
        tier = SecurityTier(_scan(vulns))
        assert tier.tier == Tier.C
        assert tier.production_ready is False


class TestRemediationScore:
    def test_all_fixable(self):
        vulns = [Vulnerability(cve_id="V1", severity=Severity.HIGH, fixed_version="1.0")]
        rs = RemediationScore(_scan(vulns))
        assert rs.value == 100

    def test_none_fixable(self):
        vulns = [Vulnerability(cve_id="V1", severity=Severity.HIGH)]
        rs = RemediationScore(_scan(vulns))
        assert rs.value == 20

    def test_no_vulns(self):
        rs = RemediationScore(_scan())
        assert rs.value == 100

    def test_partial(self):
        vulns = [
            Vulnerability(cve_id="V1", severity=Severity.HIGH, fixed_version="1.0"),
            Vulnerability(cve_id="V2", severity=Severity.HIGH),
            Vulnerability(cve_id="V3", severity=Severity.MEDIUM, fixed_version="2.0"),
            Vulnerability(cve_id="V4", severity=Severity.LOW),
        ]
        rs = RemediationScore(_scan(vulns))
        assert rs.value == 60
