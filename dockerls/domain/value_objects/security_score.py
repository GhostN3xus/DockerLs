from __future__ import annotations

from typing import TYPE_CHECKING

from dockerls.domain.entities.scan_result import ScanResult, ScanStatus

if TYPE_CHECKING:
    from dockerls.domain.entities.image import DockerImage


CRITICAL_PENALTY = 20.0
HIGH_PENALTY = 5.0
MEDIUM_PENALTY = 1.0
EOL_PENALTY = 20.0
EXPLOITED_PENALTY = 10.0
HIGH_EPSS_PENALTY = 5.0

# Qualitative bonuses. Their total is deliberately held *below* the HIGH
# penalty: no amount of "official + minimal + signed + LTS + recent" may
# lift an image with an extra HIGH or CRITICAL above a cleaner one. They
# can outweigh a MEDIUM or two, which is intended -- a signed official
# distroless image with a couple of mediums is a reasonable pick over an
# unremarkable image with none.
OFFICIAL_BONUS = 1.0
MINIMAL_BASE_BONUS = 1.0
SIGNED_BONUS = 1.0
LTS_BONUS = 0.5
RECENT_BONUS = 0.5
MAX_BONUS = OFFICIAL_BONUS + MINIMAL_BASE_BONUS + SIGNED_BONUS + LTS_BONUS + RECENT_BONUS

# Scoring starts here rather than at 100 so a fully-decorated clean image
# lands exactly on 100 without being clamped. Clamping at the top was
# collapsing genuinely different images onto the same number: a clean
# image, a 1-HIGH image and a 5-MEDIUM image all read 100.0.
BASE_SCORE = 100.0 - MAX_BONUS


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

    @property
    def penalty(self) -> float:
        """Everything measured about the image's vulnerabilities.

        This alone decides the ordering between images with different
        severity profiles -- the qualitative bonuses cannot overturn it for
        HIGH or CRITICAL findings.
        """
        penalty = (
            self._scan.critical_count * CRITICAL_PENALTY
            + self._scan.high_count * HIGH_PENALTY
            + self._scan.medium_count * MEDIUM_PENALTY
        )

        # CISA KEV / EPSS threat-intel signal: a vulnerability with a
        # confirmed real-world exploit (or a high predicted exploitation
        # probability) is materially worse than an unweighted CVSS count
        # suggests, so it draws an extra penalty on top of the base
        # severity penalties above.
        penalty += EXPLOITED_PENALTY * sum(1 for v in self._scan.vulnerabilities if v.exploit_known)
        penalty += HIGH_EPSS_PENALTY * sum(
            1 for v in self._scan.vulnerabilities if v.epss_score >= 0.5
        )

        if self._is_eol:
            penalty += EOL_PENALTY
        # Age only moves the score when the source actually reported a
        # publish date. Registries that list tag names only (Chainguard,
        # most OCI catalogues) would otherwise be charged the maximum age
        # penalty and denied the recency bonus for missing metadata.
        if self._image.age_known:
            penalty += self._image.age_days / 365.0
        return penalty

    @property
    def bonus(self) -> float:
        """Qualitative signals, capped below a single HIGH finding."""
        bonus = 0.0
        if self._image.is_official:
            bonus += OFFICIAL_BONUS
        # Distroless, hardened-vendor (Chainguard/Wolfi/Bitnami), and Alpine
        # are all "minimal base" signals; an image matching more than one
        # must not be double-counted.
        if self._image.is_distroless or self._image.is_hardened_source or self._image.is_alpine:
            bonus += MINIMAL_BASE_BONUS
        if self._image.is_signed:
            bonus += SIGNED_BONUS
        if self._is_lts:
            bonus += LTS_BONUS
        if self._image.age_known and self._image.recently_updated:
            bonus += RECENT_BONUS
        return bonus

    def _calculate(self) -> float:
        # No "zero vulnerabilities" bonus: zero findings already means zero
        # penalty, so rewarding it again double-counted the same fact and
        # was part of what pushed clean images into the clamp.
        score = BASE_SCORE - self.penalty + self.bonus
        return max(0.0, min(100.0, round(score, 1)))
