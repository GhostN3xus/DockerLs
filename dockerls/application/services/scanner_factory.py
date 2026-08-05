from __future__ import annotations

from loguru import logger

from dockerls.domain.interfaces.scanner import ScannerInterface
from dockerls.integrations.trivy.scanner import TrivyScanner
from dockerls.integrations.grype.scanner import GrypeScanner


class ScannerFactory:
    @staticmethod
    async def create() -> ScannerInterface:
        trivy = TrivyScanner()
        if await trivy.is_available():
            logger.info("Using Trivy scanner")
            return trivy

        grype = GrypeScanner()
        if await grype.is_available():
            logger.info("Trivy not available, falling back to Grype")
            return grype

        logger.warning("No scanner available, using Trivy (commands will fail)")
        return trivy
