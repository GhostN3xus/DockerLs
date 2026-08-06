from __future__ import annotations

from typing import TYPE_CHECKING

from loguru import logger

from dockerls.integrations.grype.scanner import GrypeScanner
from dockerls.integrations.trivy.scanner import TrivyScanner

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.domain.interfaces.scanner import ScannerInterface
    from dockerls.infrastructure.evidence import EvidenceStore


class ScannerFactory:
    @staticmethod
    async def create(
        timeout: int = 300,
        workers: int = 1,
        cache_dir: Path | None = None,
        evidence: EvidenceStore | None = None,
    ) -> ScannerInterface:
        trivy = TrivyScanner(
            timeout=timeout,
            workers=workers,
            cache_dir=cache_dir,
            evidence=evidence,
        )
        if await trivy.is_available():
            logger.info("Using Trivy scanner")
            return trivy

        grype = GrypeScanner(timeout=timeout, evidence=evidence)
        if await grype.is_available():
            logger.info("Trivy not available, falling back to Grype")
            return grype

        logger.warning("No scanner available, using Trivy (commands will fail)")
        return trivy

    @staticmethod
    async def create_secondary(
        primary: ScannerInterface,
        timeout: int = 300,
        evidence: EvidenceStore | None = None,
    ) -> ScannerInterface | None:
        """Return an *independent* scanner for cross-validation.

        Cross-validation is only meaningful between two different tools, so
        this returns None when the only available scanner is the one already
        producing the primary results.
        """
        if isinstance(primary, GrypeScanner):
            trivy = TrivyScanner(timeout=timeout, evidence=evidence)
            return trivy if await trivy.is_available() else None

        grype = GrypeScanner(timeout=timeout, evidence=evidence)
        if await grype.is_available():
            return grype
        logger.info("Grype not installed; cross-validation disabled")
        return None
