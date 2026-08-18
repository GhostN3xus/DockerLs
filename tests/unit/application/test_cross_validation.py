"""Cross-validation correctness and cost.

The performance assertions here are structural (call counts, observed
concurrency), not wall-clock, so they stay meaningful on a loaded CI box.
The wall-clock budget lives in the acceptance tests.
"""

from __future__ import annotations

import asyncio

import pytest

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.application.services.cross_validation import CrossValidator
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.interfaces.scanner import ScannerInterface

TS = "2026-01-01T00:00:00Z"


def _analyses(n=5, scanner="trivy", vulns=None):
    return [
        ImageAnalysis(
            image=DockerImage(name="node", tag=f"t{i}"),
            scan=ScanResult(
                image_reference=f"node:t{i}",
                scanner=scanner,
                vulnerabilities=vulns or [],
                scan_timestamp=TS,
            ),
            security_score=90.0,
            tier="A",
            remediation_score=100,
        )
        for i in range(n)
    ]


class _RecordingScanner(ScannerInterface):
    def __init__(self, vulns=None, hold=0.0):
        self.vulns = vulns or []
        self.hold = hold
        self.refresh_calls = 0
        self.scan_calls: list[str] = []
        self.in_flight = 0
        self.peak_in_flight = 0

    async def is_available(self):
        return True

    async def refresh_db(self):
        self.refresh_calls += 1
        return True

    async def scan(self, image_reference):
        self.scan_calls.append(image_reference)
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        try:
            if self.hold:
                await asyncio.sleep(self.hold)
            return ScanResult(
                image_reference=image_reference,
                scanner="grype",
                vulnerabilities=self.vulns,
                scan_timestamp=TS,
            )
        finally:
            self.in_flight -= 1


class TestDatabaseRefreshedOnce:
    @pytest.mark.asyncio
    async def test_db_refreshed_once_for_the_whole_batch(self):
        """Grype checks DB freshness on every invocation otherwise -- one
        network round trip per image, which dominated the runtime."""
        scanner = _RecordingScanner()
        await CrossValidator(scanner).validate(_analyses(5))

        assert scanner.refresh_calls == 1
        assert len(scanner.scan_calls) == 5

    @pytest.mark.asyncio
    async def test_scanner_without_refresh_hook_still_works(self):
        """The pre-fetch is opportunistic -- a scanner that has no DB to
        refresh must not be required to grow the hook."""

        class _NoRefresh(ScannerInterface):
            def __init__(self):
                self.scan_calls: list[str] = []

            async def is_available(self):
                return True

            async def scan(self, image_reference):
                self.scan_calls.append(image_reference)
                return ScanResult(
                    image_reference=image_reference, scanner="grype", scan_timestamp=TS
                )

        scanner = _NoRefresh()
        assert not hasattr(scanner, "refresh_db")
        await CrossValidator(scanner).validate(_analyses(3))

        assert len(scanner.scan_calls) == 3

    @pytest.mark.asyncio
    async def test_no_refresh_when_there_is_nothing_to_validate(self):
        scanner = _RecordingScanner()
        await CrossValidator(scanner).validate([])

        assert scanner.refresh_calls == 0
        assert scanner.scan_calls == []


class TestValidationsRunConcurrently:
    @pytest.mark.asyncio
    async def test_independent_validations_overlap(self):
        scanner = _RecordingScanner(hold=0.05)
        await CrossValidator(scanner, workers=5).validate(_analyses(5))

        assert scanner.peak_in_flight > 1, "validations still serialized"

    @pytest.mark.asyncio
    async def test_concurrency_respects_the_worker_cap(self):
        scanner = _RecordingScanner(hold=0.02)
        await CrossValidator(scanner, workers=2).validate(_analyses(6))

        assert scanner.peak_in_flight <= 2

    @pytest.mark.asyncio
    async def test_parallel_batch_is_faster_than_serial_lower_bound(self):
        hold = 0.05
        n = 6
        scanner = _RecordingScanner(hold=hold)

        start = asyncio.get_running_loop().time()
        await CrossValidator(scanner, workers=n).validate(_analyses(n))
        elapsed = asyncio.get_running_loop().time() - start

        # Serial would need n*hold; concurrent needs ~hold plus overhead.
        assert elapsed < n * hold, f"{elapsed:.3f}s is not better than serial"

    @pytest.mark.asyncio
    async def test_every_image_is_validated_exactly_once(self):
        scanner = _RecordingScanner(hold=0.01)
        items = _analyses(5)
        await CrossValidator(scanner, workers=5).validate(items)

        assert sorted(scanner.scan_calls) == sorted(a.image.full_reference for a in items)


class TestConcurrentAnnotationIsCorrect:
    @pytest.mark.asyncio
    async def test_each_analysis_gets_its_own_divergence(self):
        """Running in parallel must not cross-contaminate per-image state."""
        vulns = [Vulnerability(cve_id=f"CVE-{i}", severity=Severity.HIGH) for i in range(10)]
        scanner = _RecordingScanner(vulns=vulns, hold=0.01)
        items = _analyses(5)

        await CrossValidator(scanner, workers=5).validate(items)

        for a in items:
            # Asserted by substance rather than by wording: the message
            # names both scanners, what each found, and which findings are
            # disputed. Pinning the exact sentence would break every time
            # the explanation improves.
            assert "HIGH" in a.scan_divergence
            assert "trivy" in a.scan_divergence and "grype" in a.scan_divergence
            assert "10" in a.scan_divergence
            assert a.cross_validation == "MATERIAL_DIVERGENCE"

    @pytest.mark.asyncio
    async def test_one_failed_validation_does_not_block_the_others(self):
        class _Flaky(ScannerInterface):
            async def is_available(self):
                return True

            async def refresh_db(self):
                return True

            async def scan(self, image_reference):
                if image_reference.endswith("t2"):
                    return ScanResult(
                        image_reference=image_reference,
                        scanner="grype",
                        status=ScanStatus.ERROR,
                        error_message="grype exited 1",
                        scan_timestamp=TS,
                    )
                return ScanResult(
                    image_reference=image_reference,
                    scanner="grype",
                    vulnerabilities=[
                        Vulnerability(cve_id=f"CVE-{i}", severity=Severity.HIGH) for i in range(10)
                    ],
                    scan_timestamp=TS,
                )

        items = _analyses(5)
        await CrossValidator(_Flaky(), workers=5).validate(items)

        flagged = [a for a in items if a.scan_divergence]
        assert len(flagged) == 4
        # The failed one is left unflagged rather than falsely marked clean.
        assert items[2].scan_divergence == ""
