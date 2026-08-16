"""Every use case hands back what it borrowed.

Repositories keep one `httpx.AsyncClient` alive for the whole run so
requests reuse its connections, and scanners hold temporary Trivy cache
directories. Both are deliberately *not* context-managed per call -- that
is what makes the reuse possible -- which puts the release on whoever
started the run.

`recommend` already did this for scanners. When connection reuse arrived,
`search`, `analyze` and `compare` started leaking a client each; these
tests are what stops that from happening again.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from dockerls.application.services.teardown import close_quietly, sources_of
from dockerls.application.use_cases.analyze_image import AnalyzeImageUseCase
from dockerls.application.use_cases.compare_images import CompareImagesUseCase
from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.application.use_cases.search_images import SearchImagesUseCase


class TestCloseQuietly:
    async def test_closes_everything_that_can_be_closed(self):
        a, b = AsyncMock(), AsyncMock()
        await close_quietly(a, b)
        a.close.assert_awaited_once()
        b.close.assert_awaited_once()

    async def test_ignores_none(self):
        await close_quietly(None, None)

    async def test_ignores_an_object_with_no_close(self):
        class Bare:
            pass

        await close_quietly(Bare())

    async def test_a_failing_close_does_not_stop_the_others(self):
        """Cleanup must never replace the result the caller is returning."""
        broken = AsyncMock()
        broken.close = AsyncMock(side_effect=RuntimeError("pool already gone"))
        healthy = AsyncMock()

        await close_quietly(broken, healthy)
        healthy.close.assert_awaited_once()


class TestSourcesOf:
    def test_a_composite_yields_its_sources(self):
        class Composite:
            sources = ["a", "b"]

        assert sources_of(Composite()) == ["a", "b"]

    def test_a_plain_repository_is_its_own_source(self):
        repo = object()
        assert sources_of(repo) == [repo]

    def test_an_auto_attribute_mock_is_not_mistaken_for_a_source_list(self):
        """`AsyncMock().sources` invents a truthy attribute; treating it as
        a list of sources would close the wrong things (or nothing)."""
        mock = AsyncMock()
        assert sources_of(mock) == [mock]


class TestSearchReleasesItsClient:
    async def test_the_repository_is_closed(self):
        repo = AsyncMock()
        repo.search_tags = AsyncMock(return_value=[])
        await SearchImagesUseCase(repository=repo).execute("node")
        repo.close.assert_awaited_once()

    async def test_it_is_closed_even_when_the_search_fails(self):
        repo = AsyncMock()
        repo.search_tags = AsyncMock(side_effect=ValueError("Invalid image name"))

        with pytest.raises(ValueError, match="Invalid image name"):
            await SearchImagesUseCase(repository=repo).execute("bad name!")
        repo.close.assert_awaited_once()


class TestAnalyzeReleasesOnDemandNotPerCall:
    async def test_close_releases_scanner_and_repository(self):
        repo, scanner = AsyncMock(), AsyncMock()
        use_case = AnalyzeImageUseCase(repository=repo, scanner=scanner, eol_checker=AsyncMock())
        await use_case.close()

        scanner.close.assert_awaited_once()
        repo.close.assert_awaited_once()

    async def test_execute_does_not_close(self):
        """`compare` calls `execute` once per image; closing there would
        leave the second comparison talking to a shut-down client."""
        repo, scanner = AsyncMock(), AsyncMock()
        repo.get_image_metadata = AsyncMock(return_value=None)
        scanner.scan = AsyncMock(return_value=_clean_scan())
        eol = AsyncMock()
        eol.is_eol = AsyncMock(return_value=False)
        eol.is_lts = AsyncMock(return_value=False)

        use_case = AnalyzeImageUseCase(repository=repo, scanner=scanner, eol_checker=eol)
        await use_case.execute("node:22")

        repo.close.assert_not_awaited()
        scanner.close.assert_not_awaited()


class TestCompareReleasesOnce:
    async def test_the_inner_use_case_is_closed_after_every_image(self):
        analyze = AsyncMock()
        analyze.execute = AsyncMock(side_effect=[_analysis("node:22"), _analysis("node:20")])

        await CompareImagesUseCase(analyze_use_case=analyze).execute(["node:22", "node:20"])

        assert analyze.execute.await_count == 2
        analyze.close.assert_awaited_once()

    async def test_it_is_closed_even_when_a_scan_raises(self):
        analyze = AsyncMock()
        analyze.execute = AsyncMock(side_effect=ValueError("boom"))

        with pytest.raises(ValueError, match="boom"):
            await CompareImagesUseCase(analyze_use_case=analyze).execute(["node:22"])
        analyze.close.assert_awaited_once()


class TestRecommendStillReleasesBoth:
    async def test_scanner_and_repository_are_both_closed(self):
        repo, scanner = AsyncMock(), AsyncMock()
        repo.search_tags = AsyncMock(return_value=[])

        await RecommendImagesUseCase(
            repository=repo, scanner=scanner, eol_checker=AsyncMock()
        ).execute("node")

        scanner.close.assert_awaited_once()
        repo.close.assert_awaited_once()


def _clean_scan():
    from dockerls.domain.entities.scan_result import ScanResult

    return ScanResult(image_reference="node:22", vulnerabilities=[], scan_timestamp="t")


def _analysis(reference: str):
    from dockerls.application.dto.analysis import ImageAnalysis
    from dockerls.domain.entities.image import DockerImage

    name, tag = reference.split(":")
    return ImageAnalysis(
        image=DockerImage(name=name, tag=tag),
        scan=_clean_scan(),
        security_score=90.0,
        tier="A",
        remediation_score=100,
    )
