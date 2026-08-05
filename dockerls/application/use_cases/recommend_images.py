from __future__ import annotations

import asyncio
from typing import Any

from loguru import logger

from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.recommendation import (
    ActionType,
    Recommendation,
    RemediationStep,
)
from dockerls.domain.interfaces.cache_store import CacheStoreInterface
from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from dockerls.domain.interfaces.scanner import ScannerInterface
from dockerls.domain.value_objects.remediation_score import RemediationScore
from dockerls.domain.value_objects.security_score import SecurityScore
from dockerls.domain.value_objects.security_tier import SecurityTier


class RecommendImagesUseCase:
    def __init__(
        self,
        repository: ImageRepositoryInterface,
        scanner: ScannerInterface,
        eol_checker: EOLCheckerInterface,
        cache: CacheStoreInterface | None = None,
        max_critical: int = 0,
        max_high: int = 0,
        max_medium: int = 5,
        workers: int = 10,
    ):
        self._repository = repository
        self._scanner = scanner
        self._eol_checker = eol_checker
        self._cache = cache
        self._max_critical = max_critical
        self._max_high = max_high
        self._max_medium = max_medium
        self._workers = workers

    async def execute(self, image_name: str, limit: int = 100) -> AnalysisResult:
        tags = await self._repository.search_tags(image_name, limit=limit)
        if not tags:
            return AnalysisResult(
                query=image_name,
                total_tags_scanned=0,
                baseline_met=False,
                errors=["No tags found for image"],
            )

        semaphore = asyncio.Semaphore(self._workers)
        errors: list[str] = []

        async def analyze_tag(image: DockerImage) -> ImageAnalysis | None:
            async with semaphore:
                try:
                    cached = await self._get_cached(image.full_reference)
                    if cached:
                        return cached

                    scan = await self._scanner.scan(image.full_reference)
                    product, version = _extract_product_version(image)
                    is_eol = await self._eol_checker.is_eol(product, version)
                    is_lts = await self._eol_checker.is_lts(product, version)

                    score = SecurityScore(image, scan, is_eol=is_eol, is_lts=is_lts)
                    tier = SecurityTier(scan)
                    rem_score = RemediationScore(scan)

                    analysis = ImageAnalysis(
                        image=image,
                        scan=scan,
                        security_score=score.value,
                        tier=tier.tier.value,
                        remediation_score=rem_score.value,
                        is_eol=is_eol,
                        is_lts=is_lts,
                    )

                    await self._set_cached(image.full_reference, analysis)
                    return analysis
                except Exception as e:
                    logger.warning(f"Failed to analyze {image.full_reference}: {e}")
                    errors.append(f"{image.full_reference}: {e}")
                    return None

        tasks = [analyze_tag(tag) for tag in tags]
        results = await asyncio.gather(*tasks)
        analyses = [r for r in results if r is not None]
        analyses.sort(key=lambda a: a.security_score, reverse=True)

        baseline_images = [
            a
            for a in analyses
            if a.scan.critical_count <= self._max_critical
            and a.scan.high_count <= self._max_high
            and a.scan.medium_count <= self._max_medium
            and not a.is_eol
        ]

        if baseline_images:
            for img in baseline_images[:5]:
                img.recommendation = build_recommendation(img)
            return AnalysisResult(
                query=image_name,
                total_tags_scanned=len(tags),
                baseline_met=True,
                recommendations=baseline_images[:5],
                errors=errors,
            )

        alternatives = [
            a for a in analyses if a.scan.critical_count == 0 and not a.is_eol
        ]
        alternatives.sort(key=lambda a: (a.scan.high_count, -a.remediation_score))

        for alt in alternatives[:5]:
            alt.recommendation = build_recommendation(alt)

        return AnalysisResult(
            query=image_name,
            total_tags_scanned=len(tags),
            baseline_met=False,
            recommendations=[],
            alternatives=alternatives[:5],
            errors=errors,
        )

    async def _get_cached(self, key: str) -> Any | None:
        if self._cache:
            data = await self._cache.get(f"analysis:{key}")
            if data and isinstance(data, dict):
                return ImageAnalysis.model_validate(data)
        return None

    async def _set_cached(self, key: str, analysis: ImageAnalysis) -> None:
        if self._cache:
            await self._cache.set(
                f"analysis:{key}", analysis.model_dump(), ttl_seconds=86400
            )


def _extract_product_version(image: DockerImage) -> tuple[str, str]:
    name = image.name.split("/")[-1]
    tag = image.tag
    version = ""
    for part in tag.replace("-", ".").split("."):
        if part and part[0].isdigit():
            version = part
            break
    return name, version


def build_recommendation(analysis: ImageAnalysis) -> Recommendation:
    steps: list[RemediationStep] = []
    step_num = 1

    if analysis.scan.fixable_high_count > 0 or analysis.scan.fixable_critical_count > 0:
        fixable_pkgs = [
            v
            for v in analysis.scan.vulnerabilities
            if v.is_fixable and v.severity.value in ("CRITICAL", "HIGH")
        ]
        for vuln in fixable_pkgs[:5]:
            steps.append(
                RemediationStep(
                    step_number=step_num,
                    action=ActionType.UPDATE_PACKAGE,
                    description=f"Update {vuln.package_name}",
                    from_value=vuln.installed_version,
                    to_value=vuln.fixed_version,
                    expected_impact=f"Fix {vuln.severity.value} {vuln.cve_id}",
                )
            )
            step_num += 1

    if not analysis.image.is_alpine and not analysis.image.is_distroless:
        steps.append(
            RemediationStep(
                step_number=step_num,
                action=ActionType.SWITCH_BASE,
                description="Consider switching to Alpine or Distroless variant",
                expected_impact="Reduced attack surface",
            )
        )
        step_num += 1

    steps.append(
        RemediationStep(
            step_number=step_num,
            action=ActionType.REBUILD_IMAGE,
            description="Rebuild image to pick up latest base layer patches",
        )
    )
    step_num += 1

    steps.append(
        RemediationStep(
            step_number=step_num,
            action=ActionType.RESCAN,
            description="Re-run vulnerability scan to verify fixes",
        )
    )

    summary_parts = []
    if analysis.scan.critical_count == 0 and analysis.scan.high_count == 0:
        summary_parts.append("Image meets security baseline.")
    elif analysis.scan.critical_count == 0:
        summary_parts.append(
            f"Image has {analysis.scan.high_count} HIGH vulnerabilities "
            f"({analysis.scan.fixable_high_count} fixable)."
        )
    else:
        summary_parts.append(
            f"Image has {analysis.scan.critical_count} CRITICAL and "
            f"{analysis.scan.high_count} HIGH vulnerabilities."
        )
    if analysis.remediation_score == 100:
        summary_parts.append("All vulnerabilities have available fixes.")

    return Recommendation(
        image_reference=analysis.image.full_reference,
        security_score=analysis.security_score,
        tier=analysis.tier,
        remediation_score=analysis.remediation_score,
        steps=steps,
        summary=" ".join(summary_parts),
    )
