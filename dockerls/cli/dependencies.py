from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from dockerls.application.services.cross_validation import CrossValidator
from dockerls.application.services.scanner_factory import ScannerFactory
from dockerls.application.use_cases.analyze_image import AnalyzeImageUseCase
from dockerls.application.use_cases.compare_images import CompareImagesUseCase
from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.application.use_cases.search_images import SearchImagesUseCase
from dockerls.cache.sqlite_cache import SQLiteCache
from dockerls.infrastructure.config.settings import Settings
from dockerls.infrastructure.evidence import EvidenceStore
from dockerls.infrastructure.logging.setup import setup_logging
from dockerls.integrations.dockerhub.client import DockerHubClient
from dockerls.integrations.endoflife.checker import EndOfLifeChecker
from dockerls.integrations.threat_intel.client import ThreatIntelClient
from dockerls.utils.auth import load_credentials

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.application.services.progress import ScanObserver

# Populated by _settings() on first use; exposed so commands can tell the
# user exactly which file the run's diagnostics landed in.
_LOG_FILE: Path | None = None


@lru_cache(maxsize=1)
def _settings() -> Settings:
    global _LOG_FILE
    s = Settings()
    s.ensure_dirs()
    _LOG_FILE = setup_logging(s.log_level, log_dir=s.log_dir)
    return s


def current_log_file() -> Path | None:
    _settings()
    return _LOG_FILE


def enable_console_logging() -> None:
    """Re-attach the stderr sink (``--verbose``) on top of the file sink."""
    s = _settings()
    global _LOG_FILE
    _LOG_FILE = setup_logging(s.log_level, log_dir=s.log_dir, console=True)


def build_evidence_store() -> EvidenceStore:
    return EvidenceStore(_settings().evidence_dir)


async def build_repository(cache: SQLiteCache | None = None) -> DockerHubClient:
    s = _settings()
    username = s.dockerhub_username
    token = s.dockerhub_token
    if not username or not token:
        username, token = load_credentials()

    client = DockerHubClient(
        username=username,
        token=token,
        timeout=s.http_timeout,
        cache=cache,
    )
    if username and token:
        await client.authenticate()
    return client


def build_cache() -> SQLiteCache:
    s = _settings()
    return SQLiteCache(s.db_path)


@lru_cache(maxsize=1)
def _threat_intel() -> ThreatIntelClient | None:
    s = _settings()
    if not s.enable_threat_intel:
        return None
    return ThreatIntelClient(timeout=s.http_timeout)


async def build_recommend_use_case(
    max_critical: int = 0,
    max_high: int = 0,
    max_medium: int = 5,
    workers: int = 10,
    observer: ScanObserver | None = None,
    cross_validate: bool | None = None,
    verify_hub_tags: bool | None = None,
) -> RecommendImagesUseCase:
    s = _settings()
    cache = build_cache()
    repo = await build_repository(cache=cache)
    evidence = build_evidence_store()
    scanner = await ScannerFactory.create(
        timeout=s.scanner_timeout,
        workers=workers,
        cache_dir=s.trivy_cache_dir,
        evidence=evidence,
    )
    eol = EndOfLifeChecker(timeout=s.http_timeout)

    secondary = None
    if s.cross_validate if cross_validate is None else cross_validate:
        secondary = await ScannerFactory.create_secondary(
            scanner, timeout=s.scanner_timeout, evidence=evidence
        )

    return RecommendImagesUseCase(
        repository=repo,
        scanner=scanner,
        eol_checker=eol,
        cache=cache,
        max_critical=max_critical,
        max_high=max_high,
        max_medium=max_medium,
        workers=workers,
        threat_intel=_threat_intel(),
        observer=observer,
        cross_validator=CrossValidator(secondary),
        evidence=evidence,
        verify_hub_tags=s.verify_hub_tags if verify_hub_tags is None else verify_hub_tags,
        log_file=current_log_file(),
    )


async def build_analyze_use_case() -> AnalyzeImageUseCase:
    s = _settings()
    repo = await build_repository()
    scanner = await ScannerFactory.create(timeout=s.scanner_timeout)
    eol = EndOfLifeChecker(timeout=s.http_timeout)
    return AnalyzeImageUseCase(
        repository=repo,
        scanner=scanner,
        eol_checker=eol,
        threat_intel=_threat_intel(),
    )


async def build_compare_use_case() -> CompareImagesUseCase:
    analyze = await build_analyze_use_case()
    return CompareImagesUseCase(analyze_use_case=analyze)


async def build_search_use_case() -> SearchImagesUseCase:
    repo = await build_repository()
    return SearchImagesUseCase(repository=repo)
