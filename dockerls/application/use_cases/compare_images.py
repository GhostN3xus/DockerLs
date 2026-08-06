from __future__ import annotations

from typing import TYPE_CHECKING

from dockerls.application.dto.analysis import ComparisonResult, ImageAnalysis

if TYPE_CHECKING:
    from dockerls.application.use_cases.analyze_image import AnalyzeImageUseCase
    from dockerls.domain.entities.vulnerability import Vulnerability


class CompareImagesUseCase:
    def __init__(self, analyze_use_case: AnalyzeImageUseCase):
        self._analyze = analyze_use_case

    async def execute(self, references: list[str]) -> ComparisonResult:
        analyses: list[ImageAnalysis] = []
        for ref in references:
            analysis = await self._analyze.execute(ref)
            analyses.append(analysis)

        if not analyses:
            return ComparisonResult(images=[])

        winner = max(analyses, key=lambda a: a.security_score)

        all_cve_sets: list[set[str]] = []
        cve_map: dict[str, Vulnerability] = {}
        for a in analyses:
            cve_ids: set[str] = set()
            for v in a.scan.vulnerabilities:
                cve_ids.add(v.cve_id)
                cve_map[v.cve_id] = v
            all_cve_sets.append(cve_ids)

        common_ids = set.intersection(*all_cve_sets) if all_cve_sets else set()
        common_vulns = [cve_map[cid] for cid in common_ids if cid in cve_map]

        unique_vulns: dict[str, list[Vulnerability]] = {}
        for a, cve_ids_set in zip(analyses, all_cve_sets, strict=True):
            unique_ids = cve_ids_set - common_ids
            unique_vulns[a.image.full_reference] = [
                cve_map[uid] for uid in unique_ids if uid in cve_map
            ]

        summary_parts = [
            f"Best: {winner.image.full_reference} "
            f"(Score: {winner.security_score}, Tier: {winner.tier})"
        ]
        for a in analyses:
            if a.image.full_reference != winner.image.full_reference:
                diff = winner.security_score - a.security_score
                summary_parts.append(f"{a.image.full_reference}: -{diff:.1f} points")

        return ComparisonResult(
            images=analyses,
            winner=winner.image.full_reference,
            summary="; ".join(summary_parts),
            common_vulns=common_vulns,
            unique_vulns=unique_vulns,
        )
