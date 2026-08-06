from __future__ import annotations

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus


class SecurityScore:
    def __init__(
        self,
        image: DockerImage,
        scan: ScanResult,
        is_eol: bool = False,
        is_lts: bool = False,
    ):
        if scan.status not in (ScanStatus.OK, ScanStatus.PARTIAL):
            raise ValueError(
                f"Cannot score {image.full_reference}: scan status is "
                f"{scan.status.value} ({scan.error_message or 'no details'})"
            )
        self._image = image
        self._scan = scan
        self._is_eol = is_eol
        self._is_lts = is_lts
        self._value = self._calculate()

    @property
    def value(self) -> float:
        return self._value

    def _calculate(self) -> float:
        score = 100.0

        score -= self._scan.critical_count * 20
        score -= self._scan.high_count * 5
        score -= self._scan.medium_count * 1
        score -= self._image.age_days / 365.0

        if self._image.is_official:
            score += 5
        if self._scan.total_count == 0:
            score += 5
        # Distroless and Alpine are both "minimal base" signals; an image
        # matching both must not be double-counted.
        if self._image.is_distroless:
            score += 3
        elif self._image.is_alpine:
            score += 3
        if self._image.recently_updated:
            score += 2
        if self._image.is_signed:
            score += 2
        if self._is_lts:
            score += 2
        if self._is_eol:
            score -= 20

        return max(0.0, min(100.0, round(score, 1)))
