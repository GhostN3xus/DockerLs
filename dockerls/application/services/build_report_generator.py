"""Assembles the single record every output format is rendered from.

The terminal table, `--ci-mode` JSON, the HTML report, the SARIF upload and
the vault note all read the *same* `BuildReport`. That is the point: a
build that prints "tier A" to a developer and reports something else to CI
is worse than no report at all.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.application.dto.build import (
    BuildMetadata,
    BuildReport,
    FailingVulnerability,
    SbomInfo,
    ScannerSummary,
)
from dockerls.domain.entities.vulnerability import Severity
from dockerls.domain.value_objects.build_score import BuildScore
from dockerls.infrastructure.evidence import slugify_reference

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.application.dto.build import BuildResult
    from dockerls.domain.entities.build_validation import ValidationResult
    from dockerls.domain.entities.hardening_rule import HardeningRule
    from dockerls.domain.entities.scan_result import ScanResult

# Which severities each `--fail-on` level treats as failing.
FAIL_ON_SEVERITIES: dict[str, frozenset[Severity]] = {
    "none": frozenset(),
    "critical": frozenset({Severity.CRITICAL}),
    "high": frozenset({Severity.CRITICAL, Severity.HIGH}),
    "medium": frozenset({Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}),
}

# Exit codes, mirroring `recommend`:
#   0 = build succeeded and cleared every gate
#   1 = a hard failure (build error, blocking finding, --fail-on tripped)
#   2 = built, but findings remain that a human must look at
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_WARNINGS = 2

# How many failing CVEs a report lists by name before it stops. The full
# set is always in the scanner evidence file the report points at.
MAX_FAILING_VULNS = 50


class BuildReportGenerator:
    def generate(
        self,
        *,
        validation: ValidationResult,
        image: str,
        context_path: str,
        build: BuildResult | None = None,
        scans: list[ScanResult] | None = None,
        recommendations: list[HardeningRule] | None = None,
        metadata: BuildMetadata | None = None,
        sbom: SbomInfo | None = None,
        fail_on: str = "none",
        log_file: str = "",
    ) -> BuildReport:
        scans = scans or []
        primary = _primary_scan(scans)
        score = BuildScore(validation, primary)

        report = BuildReport(
            build_id=_build_id(),
            image=image,
            dockerfile_path=validation.dockerfile_path,
            context_path=context_path,
            validation=validation,
            build=build,
            scans=[ScannerSummary.from_scan(s) for s in scans],
            dockerfile_score=score.dockerfile_score,
            scan_score=score.scan_score,
            security_score=score.value,
            security_tier=score.tier.value,
            production_ready=score.production_ready,
            tier_advice=score.advice,
            recommendations=recommendations or [],
            failing_vulnerabilities=_failing_vulnerabilities(primary, fail_on),
            sbom=sbom,
            build_metadata=metadata or BuildMetadata(timestamp=datetime.now(tz=UTC).isoformat()),
            log_file=log_file,
        )
        report.status, report.reason = self._verdict(report, fail_on)
        return report

    def exit_code(self, report: BuildReport) -> int:
        if report.status == "FAILED":
            return EXIT_FAILED
        if report.status == "WARNING":
            return EXIT_WARNINGS
        return EXIT_OK

    def _verdict(self, report: BuildReport, fail_on: str) -> tuple[str, str]:
        """Whether this build passed, and in one sentence, why not.

        Order matters: the first *hard* reason wins, so a report never
        blames a warning for a failure that a blocking finding already
        caused.
        """
        if report.build is not None and not report.build.success:
            return "FAILED", report.build.error or "docker build failed"
        if report.validation.has_blocking_findings:
            names = ", ".join(c.check for c in report.validation.blocking)
            return "FAILED", (
                f"Dockerfile validation failed at hardening level "
                f"'{report.validation.hardening_level.value}': {names}"
            )
        if report.failing_vulnerabilities:
            return "FAILED", (
                f"--fail-on {fail_on} threshold exceeded: "
                f"{len(report.failing_vulnerabilities)} vulnerabilities at or above {fail_on}"
            )
        if report.validation.warnings:
            return "WARNING", (
                f"{len(report.validation.warnings)} advisory finding(s) require review"
            )
        return "OK", ""


def write_sbom(directory: Path, image: str, fmt: str, content: str) -> SbomInfo:
    """Persist an SBOM next to the scan evidence and count its components.

    A failed write degrades to "no SBOM recorded" rather than failing the
    build: the image is already built and scanned by this point.
    """
    path = directory / f"{slugify_reference(image)}_{slugify_reference(fmt)}.json"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as e:
        logger.warning(f"Could not write SBOM for {image}: {e}")
        return SbomInfo(fmt=fmt, file="", components_count=_count_components(content))
    return SbomInfo(fmt=fmt, file=str(path), components_count=_count_components(content))


def _count_components(content: str) -> int:
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return 0
    if not isinstance(data, dict):
        return 0
    # CycloneDX calls them components; SPDX calls them packages.
    for key in ("components", "packages"):
        value = data.get(key)
        if isinstance(value, list):
            return len(value)
    return 0


def _primary_scan(scans: list[ScanResult]) -> ScanResult | None:
    """The scan the score is derived from.

    When two scanners ran, the one reporting *more* findings is used. An
    average would let the quieter tool talk the score up, and a security
    report must not round in the reassuring direction.
    """
    usable = [s for s in scans if s.is_verified]
    if not usable:
        return None
    return max(usable, key=lambda s: (s.critical_count, s.high_count, s.total_count))


def _failing_vulnerabilities(scan: ScanResult | None, fail_on: str) -> list[FailingVulnerability]:
    severities = FAIL_ON_SEVERITIES.get(fail_on.lower(), frozenset())
    if scan is None or not severities:
        return []
    failing = [v for v in scan.vulnerabilities if v.severity in severities]
    failing.sort(key=lambda v: (-v.cvss_score, v.cve_id))
    return [
        FailingVulnerability(
            cve=v.cve_id,
            severity=v.severity.value,
            package=v.package_name,
            installed_version=v.installed_version,
            fixed_version=v.fixed_version,
            fixable=v.is_fixable,
        )
        for v in failing[:MAX_FAILING_VULNS]
    ]


def _build_id() -> str:
    return f"{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
