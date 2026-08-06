from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel

from dockerls.domain.entities.vulnerability import Severity, Vulnerability


class ScanStatus(StrEnum):
    OK = "OK"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    PARTIAL = "PARTIAL"


class ScanResult(BaseModel):
    image_reference: str
    scanner: str = "trivy"
    vulnerabilities: list[Vulnerability] = []
    scan_timestamp: str = ""
    status: ScanStatus = ScanStatus.OK
    error_message: str = ""
    # Path to the raw scanner JSON this result was parsed from, so a score
    # shown to the user can always be traced back to its source evidence.
    evidence_path: str = ""

    @property
    def is_usable(self) -> bool:
        return self.status in (ScanStatus.OK, ScanStatus.PARTIAL)

    @property
    def is_verified(self) -> bool:
        """A scan that actually completed and produced a parsed result.

        This is the gate for recommending an image: only a scanner run that
        exited cleanly (`OK`) and carries a timestamp counts as proof. A
        `PARTIAL` scan is usable for reporting but is deliberately *not*
        verified -- it means some targets could not be inspected, so its
        vulnerability counts are a lower bound, not a measurement.
        """
        return self.status is ScanStatus.OK and bool(self.scan_timestamp)

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.LOW)

    @property
    def total_count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def fixable_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.is_fixable)

    @property
    def fixable_high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.HIGH and v.is_fixable)

    @property
    def fixable_critical_count(self) -> int:
        return sum(
            1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL and v.is_fixable
        )
