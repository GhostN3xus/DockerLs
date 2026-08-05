from __future__ import annotations

import pytest

from dockerls.application.use_cases.analyze_image import AnalyzeImageUseCase
from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.application.use_cases.search_images import SearchImagesUseCase
from dockerls.application.use_cases.compare_images import CompareImagesUseCase
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Vulnerability, Severity
from dockerls.domain.interfaces.cache_store import CacheStoreInterface
from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from dockerls.domain.interfaces.scanner import ScannerInterface


class MockRepo(ImageRepositoryInterface):
    def __init__(self, tags=None):
        self._tags = tags or []

    async def search_tags(self, image_name, limit=100):
        return self._tags[:limit]

    async def get_image_metadata(self, image_name, tag):
        for t in self._tags:
            if t.tag == tag:
                return t
        return None


class MockScanner(ScannerInterface):
    def __init__(self, vulns=None):
        self._vulns = vulns or []

    async def scan(self, image_reference):
        return ScanResult(image_reference=image_reference, vulnerabilities=self._vulns)

    async def is_available(self):
        return True


class MockEOL(EOLCheckerInterface):
    async def is_eol(self, product, version):
        return False

    async def is_lts(self, product, version):
        return False


class MockCache(CacheStoreInterface):
    def __init__(self):
        self._store: dict = {}

    async def get(self, key):
        return self._store.get(key)

    async def set(self, key, value, ttl_seconds=86400):
        self._store[key] = value

    async def delete(self, key):
        self._store.pop(key, None)

    async def clear(self):
        self._store.clear()


@pytest.fixture
def tags():
    return [
        DockerImage(name="node", tag="22-alpine", is_official=True),
        DockerImage(name="node", tag="22-bookworm-slim", is_official=True),
        DockerImage(name="node", tag="20-alpine", is_official=True),
    ]


class TestSearchImages:
    @pytest.mark.asyncio
    async def test_search(self, tags):
        uc = SearchImagesUseCase(MockRepo(tags))
        result = await uc.execute("node")
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_search_empty(self):
        uc = SearchImagesUseCase(MockRepo())
        result = await uc.execute("nonexistent")
        assert len(result) == 0


class TestRecommendImages:
    @pytest.mark.asyncio
    async def test_baseline_met(self, tags):
        uc = RecommendImagesUseCase(
            repository=MockRepo(tags),
            scanner=MockScanner(),
            eol_checker=MockEOL(),
            cache=MockCache(),
        )
        result = await uc.execute("node")
        assert result.baseline_met is True
        assert len(result.recommendations) > 0

    @pytest.mark.asyncio
    async def test_fallback(self, tags):
        vulns = [Vulnerability(cve_id="H1", severity=Severity.HIGH, fixed_version="1.0")]
        uc = RecommendImagesUseCase(
            repository=MockRepo(tags),
            scanner=MockScanner(vulns),
            eol_checker=MockEOL(),
        )
        result = await uc.execute("node")
        assert result.baseline_met is False
        assert len(result.alternatives) > 0

    @pytest.mark.asyncio
    async def test_no_tags(self):
        uc = RecommendImagesUseCase(
            repository=MockRepo(),
            scanner=MockScanner(),
            eol_checker=MockEOL(),
        )
        result = await uc.execute("nothing")
        assert result.baseline_met is False
        assert len(result.errors) > 0


class TestAnalyzeImage:
    @pytest.mark.asyncio
    async def test_analyze(self, tags):
        uc = AnalyzeImageUseCase(
            repository=MockRepo(tags),
            scanner=MockScanner(),
            eol_checker=MockEOL(),
        )
        result = await uc.execute("node:22-alpine")
        assert result.security_score > 0
        assert result.tier in ("S", "A", "B", "C")

    @pytest.mark.asyncio
    async def test_parse_reference(self):
        uc = AnalyzeImageUseCase(MockRepo(), MockScanner(), MockEOL())
        assert uc._parse_reference("node:22-alpine") == ("node", "22-alpine")
        assert uc._parse_reference("python") == ("python", "latest")


class TestCompareImages:
    @pytest.mark.asyncio
    async def test_compare(self, tags):
        analyze_uc = AnalyzeImageUseCase(MockRepo(tags), MockScanner(), MockEOL())
        uc = CompareImagesUseCase(analyze_uc)
        result = await uc.execute(["node:22-alpine", "node:20-alpine"])
        assert len(result.images) == 2
        assert result.winner != ""
