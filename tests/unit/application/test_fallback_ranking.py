"""Quando nada atinge o baseline, o ranking ainda tem de sair.

O sintoma relatado: `recommend node` analisava 22 tags e respondia
"No suitable images found"; `advisor node` respondia "No images found to
advise on". A causa não era falta de compartilhamento entre os dois comandos
-- eles usam o mesmo `build_recommend_use_case` e o mesmo `execute`. Era que
o caminho "alternativas" filtrava por `critical_count == 0`, ou seja, aplicava
de novo parte do mesmo critério que o baseline acabara de rejeitar. Com toda
tag candidata carregando um CRITICAL (o caso comum no Docker Hub), as
alternativas saíam vazias também, e a execução inteira era descartada depois
de uma centena de scans.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from dockerls.domain.interfaces.scanner import ScannerInterface

# Cada tag carrega um CRITICAL -- nenhuma passa no baseline padrão.
_PROFILES = {
    "22-alpine": (1, 7),
    "22-bookworm": (6, 24),
    "20-alpine": (2, 3),
    "18-bookworm": (9, 40),
}


class _Repo(ImageRepositoryInterface):
    async def search_tags(self, image_name, limit=100):
        return [DockerImage(name="node", tag=tag) for tag in _PROFILES]

    async def get_image_metadata(self, image_name, tag):
        return None

    async def tag_exists(self, image_name, tag):
        return True


class _Scanner(ScannerInterface):
    async def is_available(self):
        return True

    async def scan(self, image_reference):
        tag = image_reference.split(":", 1)[1]
        critical, high = _PROFILES[tag]
        vulns = [
            Vulnerability(cve_id=f"C{i}-{tag}", severity=Severity.CRITICAL, fixed_version="1.1")
            for i in range(critical)
        ]
        vulns += [
            Vulnerability(cve_id=f"H{i}-{tag}", severity=Severity.HIGH, fixed_version="1.1")
            for i in range(high)
        ]
        return ScanResult(
            image_reference=image_reference,
            scan_timestamp=datetime.now(tz=UTC).isoformat(),
            vulnerabilities=vulns,
        )


class _EOL(EOLCheckerInterface):
    async def is_eol(self, product, version):
        return False

    async def is_lts(self, product, version):
        return False


def _use_case(**kwargs):
    return RecommendImagesUseCase(
        repository=_Repo(), scanner=_Scanner(), eol_checker=_EOL(), **kwargs
    )


class TestEveryCandidateHasACritical:
    @pytest.mark.asyncio
    async def test_the_run_still_produces_a_ranking(self):
        result = await _use_case().execute("node")

        assert result.baseline_met is False
        assert result.alternatives, (
            "every candidate had a CRITICAL, so the run reported nothing at all -- "
            "discarding the most useful thing it learned: which bad image is least bad"
        )

    @pytest.mark.asyncio
    async def test_the_least_bad_image_comes_first(self):
        result = await _use_case().execute("node")

        assert result.alternatives[0].image.tag == "22-alpine"

    @pytest.mark.asyncio
    async def test_the_worst_image_does_not_lead(self):
        result = await _use_case().execute("node")

        assert result.alternatives[0].image.tag != "18-bookworm"

    @pytest.mark.asyncio
    async def test_ordering_is_by_critical_then_high(self):
        result = await _use_case().execute("node")

        ordered = [(a.scan.critical_count, a.scan.high_count) for a in result.alternatives]
        assert ordered == sorted(ordered)

    @pytest.mark.asyncio
    async def test_nothing_is_presented_as_meeting_the_baseline(self):
        """Apresentar o ranking não pode virar aprovação disfarçada."""
        result = await _use_case().execute("node")

        assert result.recommendations == []
        assert result.baseline_met is False
        assert result.baseline is not None

    @pytest.mark.asyncio
    async def test_a_relaxed_baseline_promotes_them_to_recommendations(self):
        """`--max-critical`/`--max-high` continuam sendo o jeito de afrouxar
        o alvo de verdade."""
        result = await _use_case(max_critical=1, max_high=10, max_medium=50).execute("node")

        assert result.baseline_met is True
        assert [a.image.tag for a in result.recommendations] == ["22-alpine"]


class TestAdvisorSeesWhatRecommendSees:
    @pytest.mark.asyncio
    async def test_both_read_the_same_populated_result(self):
        """`advisor` lê `recommendations or alternatives` do mesmo resultado.
        Enquanto as duas listas saíam vazias, ele não tinha o que mostrar --
        não por usar outro resolver, mas porque não havia nada no objeto."""
        result = await _use_case().execute("node")

        advisor_items = result.recommendations or result.alternatives
        assert advisor_items
        assert advisor_items[0].image.tag == "22-alpine"
