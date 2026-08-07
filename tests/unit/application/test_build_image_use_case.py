"""The build pipeline's guarantees, with the daemon and scanners stubbed.

The one behaviour worth more than all the others is the ordering: a
Dockerfile that leaks a credential must never reach `docker build`. Several
tests below assert that by checking the fake builder was never called at all.
"""

from pathlib import Path

import pytest

from dockerls.application.dto.build import (
    BuildImageRequest,
    BuildResult,
    LayerInfo,
)
from dockerls.application.services.build_report_generator import (
    EXIT_FAILED,
    EXIT_OK,
    EXIT_WARNINGS,
)
from dockerls.application.services.dockerfile_validator import OwaspDockerfileValidator
from dockerls.application.services.hardening_suggester import HardeningSuggester
from dockerls.application.use_cases.analyze_dockerfile import AnalyzeDockerfileUseCase
from dockerls.application.use_cases.build_image import BuildImageUseCase
from dockerls.domain.entities.build_validation import HardeningLevel
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.exporters.build_report_exporter import BuildReportExporterFactory

CLEAN_DOCKERFILE = """\
FROM alpine:3.19 AS builder
RUN apk add --no-cache gcc

FROM alpine:3.19
LABEL maintainer="team@example.com"
LABEL security.cve-contact="security@example.com"
RUN addgroup -g 1000 g && adduser -D -u 1000 -G g appuser
COPY --from=builder --chown=appuser:g /app /app
USER appuser
HEALTHCHECK --interval=30s CMD ["/app/health"]
ENTRYPOINT ["/app/server"]
"""

LEAKY_DOCKERFILE = """\
FROM alpine:3.19
ENV NPM_TOKEN=realsecret
USER appuser
ENTRYPOINT ["/app"]
"""


class FakeBuilder:
    """Records what it was asked to do; never touches a daemon."""

    def __init__(self, available=True, success=True, push_ok=True):
        self._available = available
        self._success = success
        self._push_ok = push_ok
        self.builds = []
        self.pushes = []

    async def is_available(self):
        return self._available

    async def server_version(self):
        return "27.0.1"

    async def build(self, options):
        self.builds.append(options)
        if not self._success:
            return BuildResult(success=False, tag=options.tag, error="build blew up")
        return BuildResult(
            success=True,
            tag=options.tag,
            image_id="sha256:" + "a" * 64,
            size_bytes=142_000_000,
            layers=[LayerInfo(digest="sha256:layer", size_bytes=1000)],
            duration_seconds=45.0,
        )

    async def push(self, tag):
        self.pushes.append(tag)
        return (self._push_ok, "pushed" if self._push_ok else "denied")


class FakeScanner:
    def __init__(self, name="trivy", vulns=None, sbom='{"components": [1, 2, 3]}'):
        self.name = name
        self._vulns = vulns or []
        self._sbom = sbom
        self.scanned = []

    async def is_available(self):
        return True

    async def scan(self, tag):
        self.scanned.append(tag)
        return ScanResult(
            image_reference=tag,
            scanner=self.name,
            vulnerabilities=self._vulns,
            scan_timestamp="2026-08-07T00:00:00Z",
            status=ScanStatus.OK,
        )

    async def generate_sbom(self, tag, fmt="cyclonedx"):
        return self._sbom


def _vuln(severity, cve="CVE-2024-0001", fixed=""):
    return Vulnerability(
        cve_id=cve,
        severity=Severity(severity),
        package_name="openssl",
        installed_version="1.0",
        fixed_version=fixed,
    )


def _use_case(tmp_path, builder=None, scanner=None, secondary=None, level=None, **kwargs):
    validator = OwaspDockerfileValidator(
        hardening_level=level or HardeningLevel.STANDARD, suggester=HardeningSuggester()
    )
    return BuildImageUseCase(
        analyzer=AnalyzeDockerfileUseCase(validator),
        builder=builder or FakeBuilder(),
        scanner=scanner,
        secondary_scanner=secondary,
        exporter_factory=BuildReportExporterFactory,
        sbom_dir=tmp_path / "sboms",
        report_dir=tmp_path / "reports",
        **kwargs,
    )


def _context(tmp_path, dockerfile=CLEAN_DOCKERFILE):
    (tmp_path / "Dockerfile").write_text(dockerfile)
    (tmp_path / ".dockerignore").write_text(".git\n.env\n")
    return tmp_path


def _request(context, **kwargs):
    kwargs.setdefault("tag", "myapp:1.0")
    kwargs.setdefault("scan", False)
    kwargs.setdefault("generate_sbom", False)
    return BuildImageRequest(context_path=str(context), **kwargs)


class TestHappyPath:
    async def test_a_valid_dockerfile_builds(self, tmp_path):
        builder = FakeBuilder()
        response = await _use_case(tmp_path, builder).execute(_request(_context(tmp_path)))
        assert response.success
        assert response.exit_code == EXIT_OK
        assert builder.builds[0].tag == "myapp:1.0"

    async def test_the_report_records_what_was_built(self, tmp_path):
        response = await _use_case(tmp_path).execute(_request(_context(tmp_path)))
        report = response.report
        assert report.build.success
        assert report.build.size_human == "135.4 MB"
        assert report.image == "myapp:1.0"
        assert report.security_tier in ("S", "A")

    async def test_provenance_labels_are_added_automatically(self, tmp_path):
        builder = FakeBuilder()
        await _use_case(tmp_path, builder).execute(_request(_context(tmp_path)))
        labels = builder.builds[0].labels
        assert labels["security.scanner"] == "dockerls"
        assert "org.opencontainers.image.created" in labels

    async def test_user_labels_win_over_generated_ones(self, tmp_path):
        builder = FakeBuilder()
        request = _request(_context(tmp_path), labels={"security.scanner": "mine"})
        await _use_case(tmp_path, builder).execute(request)
        assert builder.builds[0].labels["security.scanner"] == "mine"


class TestValidationGate:
    async def test_a_leaked_credential_stops_the_build_before_it_starts(self, tmp_path):
        builder = FakeBuilder()
        context = _context(tmp_path, LEAKY_DOCKERFILE)
        response = await _use_case(tmp_path, builder).execute(_request(context))

        assert builder.builds == [], "a Dockerfile with a baked-in secret must never be built"
        assert not response.success
        assert response.exit_code == EXIT_FAILED
        assert "secrets_not_in_env" in response.report.reason

    async def test_force_builds_anyway_and_still_reports_the_finding(self, tmp_path):
        builder = FakeBuilder()
        context = _context(tmp_path, LEAKY_DOCKERFILE)
        response = await _use_case(tmp_path, builder).execute(_request(context, force=True))

        assert builder.builds, "--force must actually build"
        assert any(c.check == "secrets_not_in_env" for c in response.report.validation.failures)

    async def test_relaxed_level_tolerates_a_high_finding(self, tmp_path):
        builder = FakeBuilder()
        context = _context(tmp_path, 'FROM node:latest\nUSER app\nENTRYPOINT ["/a"]\n')
        use_case = _use_case(tmp_path, builder, level=HardeningLevel.RELAXED)
        await use_case.execute(_request(context))
        assert builder.builds

    async def test_strict_level_blocks_on_a_medium_finding(self, tmp_path):
        builder = FakeBuilder()
        context = _context(tmp_path, 'FROM ubuntu:24.04\nUSER app\nENTRYPOINT ["/a"]\n')
        use_case = _use_case(tmp_path, builder, level=HardeningLevel.STRICT)
        response = await use_case.execute(_request(context))
        assert builder.builds == []
        assert response.exit_code == EXIT_FAILED


class TestDryRunModes:
    async def test_validate_only_never_builds(self, tmp_path):
        builder = FakeBuilder()
        response = await _use_case(tmp_path, builder).execute(
            _request(_context(tmp_path), validate_only=True, tag="")
        )
        assert builder.builds == []
        assert response.report.build is None
        assert response.success

    async def test_suggest_only_returns_recommendations_without_building(self, tmp_path):
        builder = FakeBuilder()
        context = _context(tmp_path, 'FROM node:latest\nUSER app\nENTRYPOINT ["/a"]\n')
        response = await _use_case(tmp_path, builder).execute(
            _request(context, suggest_only=True, tag="")
        )
        assert builder.builds == []
        rules = {r.rule_id for r in response.report.recommendations}
        assert "base_image_pinned" in rules
        assert "base_image_upgrade" in rules

    async def test_validate_only_does_not_scan(self, tmp_path):
        scanner = FakeScanner()
        await _use_case(tmp_path, scanner=scanner).execute(
            _request(_context(tmp_path), validate_only=True, tag="", scan=True)
        )
        assert scanner.scanned == []


class TestScanning:
    async def test_the_built_image_is_scanned(self, tmp_path):
        scanner = FakeScanner(vulns=[_vuln("MEDIUM")])
        response = await _use_case(tmp_path, scanner=scanner).execute(
            _request(_context(tmp_path), scan=True)
        )
        assert scanner.scanned == ["myapp:1.0"]
        assert response.report.scans[0].medium == 1

    async def test_both_scanners_are_reported_separately(self, tmp_path):
        primary = FakeScanner("trivy", [_vuln("MEDIUM")])
        secondary = FakeScanner("grype", [_vuln("MEDIUM"), _vuln("MEDIUM", "CVE-2024-0002")])
        response = await _use_case(tmp_path, scanner=primary, secondary=secondary).execute(
            _request(_context(tmp_path), scan=True)
        )
        assert {s.scanner for s in response.report.scans} == {"trivy", "grype"}

    async def test_the_worse_scan_drives_the_score(self, tmp_path):
        """Averaging two scanners would let the quieter tool talk the score
        up; a security report must not round in the reassuring direction."""
        quiet = FakeScanner("trivy", [])
        loud = FakeScanner("grype", [_vuln("CRITICAL")])
        response = await _use_case(tmp_path, scanner=quiet, secondary=loud).execute(
            _request(_context(tmp_path), scan=True)
        )
        assert response.report.security_tier == "C"

    async def test_a_scanner_crash_does_not_lose_the_build(self, tmp_path):
        class Exploding(FakeScanner):
            async def scan(self, tag):
                raise OSError("scanner died")

        response = await _use_case(tmp_path, scanner=Exploding()).execute(
            _request(_context(tmp_path), scan=True)
        )
        assert response.report.build.success
        assert response.report.scans == []

    async def test_no_scan_means_the_score_reports_no_scan_score(self, tmp_path):
        response = await _use_case(tmp_path).execute(_request(_context(tmp_path), scan=False))
        assert response.report.scan_score is None


class TestFailOn:
    @pytest.mark.parametrize(
        ("fail_on", "severity", "expect_failure"),
        [
            ("critical", "CRITICAL", True),
            ("critical", "HIGH", False),
            ("high", "HIGH", True),
            ("high", "MEDIUM", False),
            ("medium", "MEDIUM", True),
            ("none", "CRITICAL", False),
        ],
    )
    async def test_threshold_decides_the_exit_code(
        self, tmp_path, fail_on, severity, expect_failure
    ):
        scanner = FakeScanner(vulns=[_vuln(severity)])
        response = await _use_case(tmp_path, scanner=scanner).execute(
            _request(_context(tmp_path), scan=True, fail_on=fail_on)
        )
        assert (response.exit_code == EXIT_FAILED) is expect_failure

    async def test_failing_cves_are_named_not_just_counted(self, tmp_path):
        scanner = FakeScanner(vulns=[_vuln("HIGH", "CVE-2024-1234", fixed="1.1")])
        response = await _use_case(tmp_path, scanner=scanner).execute(
            _request(_context(tmp_path), scan=True, fail_on="high")
        )
        failing = response.report.failing_vulnerabilities
        assert failing[0].cve == "CVE-2024-1234"
        assert failing[0].fixable is True


class TestExitCodes:
    async def test_warnings_exit_with_two_not_one(self, tmp_path):
        """A build worth reviewing must be distinguishable from one that
        failed, or a pipeline cannot decide whether to stop."""
        context = _context(tmp_path, 'FROM alpine:3.19\nUSER app\nENTRYPOINT ["/a"]\n')
        response = await _use_case(tmp_path).execute(_request(context))
        assert response.report.status == "WARNING"
        assert response.exit_code == EXIT_WARNINGS

    async def test_a_broken_build_exits_one(self, tmp_path):
        builder = FakeBuilder(success=False)
        response = await _use_case(tmp_path, builder).execute(_request(_context(tmp_path)))
        assert response.exit_code == EXIT_FAILED
        assert "build blew up" in response.report.reason

    async def test_an_unreachable_daemon_is_reported_not_crashed(self, tmp_path):
        builder = FakeBuilder(available=False)
        response = await _use_case(tmp_path, builder).execute(_request(_context(tmp_path)))
        assert response.exit_code == EXIT_FAILED
        assert "daemon" in response.report.build.error


class TestSbomAndReports:
    async def test_sbom_is_written_and_counted(self, tmp_path):
        scanner = FakeScanner()
        response = await _use_case(tmp_path, scanner=scanner).execute(
            _request(_context(tmp_path), scan=True, generate_sbom=True)
        )
        sbom = response.report.sbom
        assert sbom.components_count == 3
        assert Path(sbom.file).exists()

    async def test_requested_report_formats_are_written(self, tmp_path):
        response = await _use_case(tmp_path).execute(
            _request(_context(tmp_path), report_formats=["json", "html", "sarif"])
        )
        assert len(response.written_reports) == 3
        for path in response.written_reports:
            assert Path(path).exists()

    async def test_report_path_extension_picks_the_format(self, tmp_path):
        target = tmp_path / "out" / "report.html"
        response = await _use_case(tmp_path).execute(
            _request(_context(tmp_path), report_path=str(target))
        )
        assert target.read_text().startswith("<!DOCTYPE html>")
        assert response.written_reports == [str(target)]

    async def test_an_unwritable_report_does_not_lose_the_verdict(self, tmp_path):
        blocked = tmp_path / "Dockerfile" / "report.json"
        response = await _use_case(tmp_path).execute(
            _request(_context(tmp_path), report_path=str(blocked))
        )
        assert response.written_reports == []
        assert response.report.status in ("OK", "WARNING")


class TestPush:
    async def test_a_passing_build_is_pushed(self, tmp_path):
        builder = FakeBuilder()
        response = await _use_case(tmp_path, builder).execute(
            _request(_context(tmp_path), push=True)
        )
        assert builder.pushes == ["myapp:1.0"]
        assert response.pushed

    async def test_a_failing_build_is_never_pushed(self, tmp_path):
        builder = FakeBuilder()
        context = _context(tmp_path, LEAKY_DOCKERFILE)
        response = await _use_case(tmp_path, builder).execute(_request(context, push=True))
        assert builder.pushes == [], "--push must not publish an image that failed its gate"
        assert "Not pushed" in response.push_message

    async def test_a_failed_push_fails_the_run(self, tmp_path):
        builder = FakeBuilder(push_ok=False)
        response = await _use_case(tmp_path, builder).execute(
            _request(_context(tmp_path), push=True)
        )
        assert not response.pushed
        assert response.exit_code == EXIT_FAILED


class TestVault:
    async def test_vault_push_writes_a_note(self, tmp_path):
        from dockerls.infrastructure.vault.vault_pusher import VaultPusher

        vault = VaultPusher(tmp_path / "vault")
        use_case = _use_case(tmp_path, vault=vault)
        response = await use_case.execute(_request(_context(tmp_path)))
        await use_case.push_to_vault(response, "infra/containers/myapp")
        assert Path(response.vault_note).exists()
        assert "Build Hardening Report" in Path(response.vault_note).read_text()

    async def test_a_traversing_vault_path_is_refused(self, tmp_path):
        from dockerls.infrastructure.vault.vault_pusher import VaultPusher

        use_case = _use_case(tmp_path, vault=VaultPusher(tmp_path / "vault"))
        response = await use_case.execute(_request(_context(tmp_path)))
        await use_case.push_to_vault(response, "../../etc")
        assert "escapes" in response.vault_note

    async def test_vault_push_without_a_configured_root_says_so(self, tmp_path):
        use_case = _use_case(tmp_path)
        response = await use_case.execute(_request(_context(tmp_path)))
        await use_case.push_to_vault(response, "builds")
        assert "no vault root" in response.vault_note


class TestMissingDockerfile:
    async def test_a_missing_dockerfile_is_a_clear_error(self, tmp_path):
        with pytest.raises(ValueError, match="No Dockerfile"):
            await _use_case(tmp_path).execute(_request(tmp_path))
