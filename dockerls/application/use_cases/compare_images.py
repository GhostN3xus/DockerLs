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

        # Uma linha só, com vencedor, score absoluto e delta misturados e
        # separados por ponto e vírgula, produzia
        # `...; node:22-bookworm-slim: -36.0 points` -- em que o `-36.0` lê
        # como um score negativo em vez de uma diferença. Os dados vão
        # estruturados; quem renderiza decide o formato.
        return ComparisonResult(
            images=analyses,
            winner=winner.image.full_reference,
            summary=(
                f"{winner.image.full_reference} scores highest "
                f"({winner.security_score}, tier {winner.tier})"
            ),
            common_vulns=common_vulns,
            unique_vulns=unique_vulns,
        )
