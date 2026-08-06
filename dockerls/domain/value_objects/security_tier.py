from __future__ import annotations

from enum import Enum

from dockerls.domain.entities.scan_result import ScanResult


class Tier(str, Enum):
    S = "S"
    A = "A"
    B = "B"
    C = "C"


class SecurityTier:
    def __init__(self, scan: ScanResult, is_eol: bool = False):
        self._scan = scan
        self._is_eol = is_eol
        self._tier = self._classify()

    @property
    def tier(self) -> Tier:
        return self._tier

    @property
    def production_ready(self) -> bool:
        # An EOL base is never production-ready, regardless of its
        # vulnerability tier -- it will stop receiving security patches.
        if self._is_eol:
            return False
        return self._tier != Tier.C

    def _classify(self) -> Tier:
        c = self._scan.critical_count
        h = self._scan.high_count
        fixable_h = self._scan.fixable_high_count

        if c == 0 and h == 0:
            return Tier.S

        if c == 0 and h <= 3 and fixable_h == h:
            return Tier.A

        if c == 0 and h <= 10:
            return Tier.B

        return Tier.C
