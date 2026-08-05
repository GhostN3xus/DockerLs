from __future__ import annotations

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from dockerls.domain.interfaces.scanner import ScannerInterface
from dockerls.domain.value_objects.remediation_score import RemediationScore
from dockerls.domain.value_objects.security_score import SecurityScore
from dockerls.domain.value_objects.security_tier import SecurityTier


class AnalyzeImageUseCase:
    def __init__(
        self,
        repository: ImageRepositoryInterface,
        scanner: ScannerInterface,
        eol_checker: EOLCheckerInterface,
    ):
        self._repository = repository
        self._scanner = scanner
        self._eol_checker = eol_checker

    async def execute(self, image_reference: str) -> ImageAnalysis:
        name, tag = self._parse_reference(image_reference)
        image = await self._repository.get_image_metadata(name, tag)
        if not image:
            image = DockerImage(name=name, tag=tag)

        scan = await self._scanner.scan(image.full_reference)

        product = name.split("/")[-1]
        version = ""
        for part in tag.replace("-", ".").split("."):
            if part and part[0].isdigit():
                version = part
                break

        is_eol = await self._eol_checker.is_eol(product, version)
        is_lts = await self._eol_checker.is_lts(product, version)

        score = SecurityScore(image, scan, is_eol=is_eol, is_lts=is_lts)
        tier = SecurityTier(scan)
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

    def _parse_reference(self, reference: str) -> tuple[str, str]:
        if ":" in reference:
            parts = reference.rsplit(":", 1)
            return parts[0], parts[1]
        return reference, "latest"
