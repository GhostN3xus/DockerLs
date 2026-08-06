from __future__ import annotations

from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from dockerls.application.dto.analysis import ImageAnalysis
    from dockerls.domain.entities.scan_result import ScanResult
    from dockerls.domain.interfaces.scanner import ScannerInterface

# A second scanner never reproduces the first one's counts exactly -- the
# databases differ and each maps severities its own way. Only a difference
# that is both large in absolute terms *and* large relative to the primary
# count is treated as a real disagreement worth flagging.
DEFAULT_ABS_TOLERANCE = 2
DEFAULT_REL_TOLERANCE = 0.5


class CrossValidator:
    """Re-scans top candidates with a second scanner and flags material
    disagreements, so a score is never presented at full confidence when
    two independent scanners tell different stories."""

    def __init__(
        self,
        scanner: ScannerInterface | None,
        abs_tolerance: int = DEFAULT_ABS_TOLERANCE,
        rel_tolerance: float = DEFAULT_REL_TOLERANCE,
    ):
        self._scanner = scanner
        self._abs_tolerance = abs_tolerance
        self._rel_tolerance = rel_tolerance

    @property
    def enabled(self) -> bool:
        return self._scanner is not None

    @property
    def scanner(self) -> ScannerInterface | None:
        return self._scanner

    async def validate(self, analyses: list[ImageAnalysis]) -> None:
        """Annotate each analysis in place with `scan_divergence` and the
        secondary scanner's evidence path."""
        if self._scanner is None or not analyses:
            return
        if not await self._scanner.is_available():
            logger.info("Cross-validation scanner unavailable; skipping")
            return

        for analysis in analyses:
            await self._validate_one(analysis)

    async def _validate_one(self, analysis: ImageAnalysis) -> None:
        if self._scanner is None:
            return
        reference = analysis.image.full_reference
        secondary = await self._scanner.scan(reference)

        if not secondary.is_verified:
            logger.warning(
                f"Cross-validation of {reference} did not complete "
                f"({secondary.status.value}: {secondary.error_message or 'no details'})"
            )
            return

        if secondary.evidence_path:
            analysis.evidence_paths[secondary.scanner] = secondary.evidence_path

        divergence = self._describe_divergence(analysis, secondary)
        if divergence:
            logger.warning(f"Scanner divergence for {reference}: {divergence}")
            analysis.scan_divergence = divergence

    def _describe_divergence(self, analysis: ImageAnalysis, secondary: ScanResult) -> str:
        primary = analysis.scan
        parts: list[str] = []
        for label in ("critical", "high"):
            a: int = getattr(primary, f"{label}_count")
            b: int = getattr(secondary, f"{label}_count")
            if self._is_material(a, b):
                parts.append(f"{label.upper()} {primary.scanner}={a} vs {secondary.scanner}={b}")
        return "; ".join(parts)

    def _is_material(self, primary: int, secondary: int) -> bool:
        delta = abs(primary - secondary)
        if delta <= self._abs_tolerance:
            return False
        baseline = max(primary, secondary, 1)
        return (delta / baseline) > self._rel_tolerance
