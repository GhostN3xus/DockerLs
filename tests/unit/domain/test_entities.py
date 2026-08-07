from datetime import UTC, datetime, timedelta

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.recommendation import ActionType, Recommendation, RemediationStep
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import FixStatus, Severity, Vulnerability


class TestDockerImage:
    def test_full_reference(self):
        img = DockerImage(name="node", tag="22-alpine")
        assert img.full_reference == "node:22-alpine"

    def test_is_alpine(self):
        img = DockerImage(name="node", tag="22-alpine")
        assert img.is_alpine is True
        img2 = DockerImage(name="node", tag="22-bookworm")
        assert img2.is_alpine is False

    def test_is_distroless(self):
        img = DockerImage(name="gcr.io/distroless/static", tag="latest")
        assert img.is_distroless is True

    def test_age_days_no_update(self):
        img = DockerImage(name="node", tag="latest")
        assert img.age_days == 365

    def test_age_days_recent(self):
        now = datetime.now(tz=UTC)
        img = DockerImage(name="node", tag="latest", last_updated=now - timedelta(days=5))
        assert img.age_days == 5

    def test_recently_updated(self):
        now = datetime.now(tz=UTC)
        img = DockerImage(name="node", tag="latest", last_updated=now - timedelta(days=10))
        assert img.recently_updated is True
        img2 = DockerImage(name="node", tag="latest", last_updated=now - timedelta(days=60))
        assert img2.recently_updated is False


class TestVulnerability:
    def test_fix_available(self):
        v = Vulnerability(cve_id="CVE-2024-0001", severity=Severity.HIGH, fixed_version="1.2.3")
        assert v.fix_status == FixStatus.FIX_AVAILABLE
        assert v.is_fixable is True

    def test_no_fix(self):
        v = Vulnerability(cve_id="CVE-2024-0002", severity=Severity.CRITICAL)
        assert v.fix_status == FixStatus.NO_FIX
        assert v.is_fixable is False


class TestScanResult:
    def _make_scan(self):
        return ScanResult(
            image_reference="node:22-alpine",
            vulnerabilities=[
                Vulnerability(cve_id="CVE-1", severity=Severity.CRITICAL, fixed_version="1.0"),
                Vulnerability(cve_id="CVE-2", severity=Severity.HIGH, fixed_version="2.0"),
                Vulnerability(cve_id="CVE-3", severity=Severity.HIGH),
                Vulnerability(cve_id="CVE-4", severity=Severity.MEDIUM),
                Vulnerability(cve_id="CVE-5", severity=Severity.LOW),
            ],
        )

    def test_counts(self):
        scan = self._make_scan()
        assert scan.critical_count == 1
        assert scan.high_count == 2
        assert scan.medium_count == 1
        assert scan.low_count == 1
        assert scan.total_count == 5

    def test_fixable_counts(self):
        scan = self._make_scan()
        assert scan.fixable_count == 2
        assert scan.fixable_high_count == 1
        assert scan.fixable_critical_count == 1


class TestRecommendation:
    def test_create(self):
        rec = Recommendation(
            image_reference="node:22-alpine",
            security_score=95.0,
            tier="S",
            remediation_score=100,
            steps=[
                RemediationStep(
                    step_number=1,
                    action=ActionType.REBUILD_IMAGE,
                    description="Rebuild",
                )
            ],
        )
        assert rec.tier == "S"
        assert len(rec.steps) == 1
