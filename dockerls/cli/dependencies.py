from __future__ import annotations

from dockerls.application.services.scanner_factory import ScannerFactory
from dockerls.application.use_cases.analyze_image import AnalyzeImageUseCase
from dockerls.application.use_cases.compare_images import CompareImagesUseCase
from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.application.use_cases.search_images import SearchImagesUseCase
from dockerls.cache.sqlite_cache import SQLiteCache
from dockerls.infrastructure.config.settings import Settings
from dockerls.infrastructure.logging.setup import setup_logging
from dockerls.integrations.dockerhub.client import DockerHubClient
from dockerls.integrations.endoflife.checker import EndOfLifeChecker


def _settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    setup_logging(s.log_level)
    return s


def build_repository() -> DockerHubClient:
    s = _settings()
    return DockerHubClient(
        username=s.dockerhub_username,
        token=s.dockerhub_token,
        timeout=s.http_timeout,
    )


def build_cache() -> SQLiteCache:
    s = _settings()
    return SQLiteCache(s.db_path)


async def build_recommend_use_case(
    max_critical: int = 0,
    max_high: int = 0,
    max_medium: int = 5,
    workers: int = 10,
) -> RecommendImagesUseCase:
    s = _settings()
    repo = build_repository()
    scanner = await ScannerFactory.create()
    eol = EndOfLifeChecker(timeout=s.http_timeout)
    cache = build_cache()

    return RecommendImagesUseCase(
        repository=repo,
        scanner=scanner,
        eol_checker=eol,
        cache=cache,
        max_critical=max_critical,
        max_high=max_high,
        max_medium=max_medium,
        workers=workers,
    )


async def build_analyze_use_case() -> AnalyzeImageUseCase:
    s = _settings()
    repo = build_repository()
    scanner = await ScannerFactory.create()
    eol = EndOfLifeChecker(timeout=s.http_timeout)
    return AnalyzeImageUseCase(repository=repo, scanner=scanner, eol_checker=eol)


async def build_compare_use_case() -> CompareImagesUseCase:
    analyze = await build_analyze_use_case()
    return CompareImagesUseCase(analyze_use_case=analyze)


async def build_search_use_case() -> SearchImagesUseCase:
    repo = build_repository()
    return SearchImagesUseCase(repository=repo)
