from __future__ import annotations

from dockerls.domain.entities.scan_result import ScanResult


class RemediationScore:
    def __init__(self, scan: ScanResult):
        self._scan = scan
        self._value = self._calculate()

    @property
    def value(self) -> int:
        return self._value

    def _calculate(self) -> int:
        total = self._scan.total_count
        if total == 0:
            return 100

        fixable = self._scan.fixable_count
        ratio = fixable / total

        if ratio >= 1.0:
            return 100
        if ratio >= 0.75:
            return 80
        if ratio >= 0.5:
            return 60
        if ratio >= 0.25:
            return 40
        return 20
