from datetime import datetime, timezone, timedelta

import pytest

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Vulnerability, Severity
from dockerls.domain.value_objects.security_score import SecurityScore
from dockerls.domain.value_objects.security_tier import SecurityTier, Tier
from dockerls.domain.value_objects.remediation_score import RemediationScore


def _image(**kwargs):
    defaults = {"name": "node", "tag": "22-alpine", "is_official": True,
                "last_updated": datetime.now(tz=timezone.utc) - timedelta(days=5)}
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
        img = _image(last_updated=datetime.now(tz=timezone.utc))
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
            image_reference="node:22-alpine", status=ScanStatus.ERROR,
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
