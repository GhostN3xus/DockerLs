from __future__ import annotations

from pydantic import BaseModel

from dockerls.domain.entities.vulnerability import Severity, Vulnerability


class ScanResult(BaseModel):
    image_reference: str
    scanner: str = "trivy"
    vulnerabilities: list[Vulnerability] = []
    scan_timestamp: str = ""

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
        return sum(
            1 for v in self.vulnerabilities
            if v.severity == Severity.HIGH and v.is_fixable
        )

    @property
    def fixable_critical_count(self) -> int:
        return sum(
            1 for v in self.vulnerabilities
            if v.severity == Severity.CRITICAL and v.is_fixable
        )
