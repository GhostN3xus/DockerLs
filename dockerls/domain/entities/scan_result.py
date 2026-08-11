from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel

from dockerls.domain.entities.vulnerability import Severity, Vulnerability


class ScanStatus(StrEnum):
    OK = "OK"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"
    PARTIAL = "PARTIAL"


class ScanErrorKind(StrEnum):
    """Why a scan failed, as a stable code rather than a slice of stderr.

    A terminal column can only hold a few characters, and truncating the raw
    message produced things like `error in v...` -- which names no cause and
    cannot be grouped, counted, or acted on. The full stderr is still kept in
    `error_message` (log file and `--format json`); this is what the table
    shows instead of a cut-off prefix.

    It also decides *retryability*: a broken vulnerability database is the
    scanner's problem and another scanner may well succeed, while a tag that
    does not exist will fail identically no matter who is asked.
    """

    NONE = "NONE"
    DB_INIT_FAILED = "DB_INIT_FAILED"
    TIMEOUT = "TIMEOUT"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    NOT_FOUND = "NOT_FOUND"
    RATE_LIMITED = "RATE_LIMITED"
    INVALID_OUTPUT = "INVALID_OUTPUT"
    SCANNER_MISSING = "SCANNER_MISSING"
    UNKNOWN = "UNKNOWN"

    @property
    def is_scanner_fault(self) -> bool:
        """True when a *different* scanner has a real chance of succeeding.

        `NOT_FOUND` and `AUTH_REQUIRED` are facts about the image, so retrying
        them with another tool just doubles the wait for the same answer.
        """
        return self in (
            ScanErrorKind.DB_INIT_FAILED,
            ScanErrorKind.TIMEOUT,
            ScanErrorKind.RATE_LIMITED,
            ScanErrorKind.INVALID_OUTPUT,
            ScanErrorKind.SCANNER_MISSING,
            ScanErrorKind.UNKNOWN,
        )


class ScanResult(BaseModel):
    image_reference: str
    scanner: str = "trivy"
    vulnerabilities: list[Vulnerability] = []
    scan_timestamp: str = ""
    status: ScanStatus = ScanStatus.OK
    error_message: str = ""
    # Classified reason for a failure. `error_message` keeps the full stderr;
    # this is the part that fits in a table and can be grouped across tags.
    error_kind: ScanErrorKind = ScanErrorKind.NONE
    # Path to the raw scanner JSON this result was parsed from, so a score
    # shown to the user can always be traced back to its source evidence.
    evidence_path: str = ""

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
