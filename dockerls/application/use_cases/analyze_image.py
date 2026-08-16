from __future__ import annotations

import re
from typing import TYPE_CHECKING

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.application.services.teardown import close_quietly, sources_of
from dockerls.application.use_cases.recommend_images import _enrich_with_threat_intel
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.value_objects.remediation_score import RemediationScore
from dockerls.domain.value_objects.security_score import SecurityScore
from dockerls.domain.value_objects.security_tier import SecurityTier
from dockerls.utils.ignore_file import active_ignored_cve_ids, load_ignore_rules

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
    from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
    from dockerls.domain.interfaces.scanner import ScannerInterface
    from dockerls.integrations.threat_intel.client import ThreatIntelClient


class AnalyzeImageUseCase:
    def __init__(
        self,
        repository: ImageRepositoryInterface,
        scanner: ScannerInterface,
        eol_checker: EOLCheckerInterface,
        ignore_path: Path | None = None,
        threat_intel: ThreatIntelClient | None = None,
    ):
        self._repository = repository
        self._scanner = scanner
        self._eol_checker = eol_checker
        self._ignored_cves = active_ignored_cve_ids(load_ignore_rules(ignore_path))
        self._threat_intel = threat_intel

    async def execute(self, image_reference: str) -> ImageAnalysis:
        name, tag = self._parse_reference(image_reference)
        image = await self._repository.get_image_metadata(name, tag)
        if not image:
            image = DockerImage(name=name, tag=tag)

        scan = await self._scanner.scan(image.full_reference)
        if self._ignored_cves:
            filtered = [
                v for v in scan.vulnerabilities if v.cve_id.upper() not in self._ignored_cves
            ]
            if len(filtered) != len(scan.vulnerabilities):
                scan = scan.model_copy(update={"vulnerabilities": filtered})
        if self._threat_intel is not None:
            scan = await _enrich_with_threat_intel(scan, self._threat_intel)

        product = name.split("/")[-1]
        match = re.match(r"^\d+(?:\.\d+){0,3}", tag)
        version = match.group(0) if match else ""

        is_eol = await self._eol_checker.is_eol(product, version)
        is_lts = await self._eol_checker.is_lts(product, version)

        score = SecurityScore(image, scan, is_eol=is_eol, is_lts=is_lts)
        tier = SecurityTier(scan, score.value, is_eol=is_eol)
        rem_score = RemediationScore(scan)

        return ImageAnalysis(
            image=image,
            scan=scan,
            security_score=score.value,
            tier=tier.tier.value,
            remediation_score=rem_score.value,
            is_eol=is_eol,
            is_lts=is_lts,
        )

    async def close(self) -> None:
        """Release the scanner and the repository's connection pool.

        Not done inside `execute`, because `CompareImagesUseCase` calls it
        once per image: closing there would leave the second comparison
        talking to a client that had already been shut down.
        """
        await close_quietly(self._scanner, *sources_of(self._repository))

    def _parse_reference(self, reference: str) -> tuple[str, str]:
        if ":" in reference:
            parts = reference.rsplit(":", 1)
            return parts[0], parts[1]
        return reference, "latest"
