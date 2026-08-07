from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING

from dockerls.application.services.build_report_generator import BuildReportGenerator
from dockerls.application.services.composite_repository import CompositeImageRepository
from dockerls.application.services.cross_validation import CrossValidator
from dockerls.application.services.dockerfile_validator import OwaspDockerfileValidator
from dockerls.application.services.hardening_suggester import HardeningSuggester
from dockerls.application.services.scanner_factory import ScannerFactory
from dockerls.application.use_cases.analyze_dockerfile import AnalyzeDockerfileUseCase
from dockerls.application.use_cases.analyze_image import AnalyzeImageUseCase
from dockerls.application.use_cases.build_image import BuildImageUseCase
from dockerls.application.use_cases.compare_images import CompareImagesUseCase
from dockerls.application.use_cases.generate_hardened_dockerfile import (
    GenerateHardenedDockerfileUseCase,
)
from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.application.use_cases.search_images import SearchImagesUseCase
from dockerls.cache.sqlite_cache import SQLiteCache
from dockerls.domain.entities.build_validation import HardeningLevel
from dockerls.exporters.build_report_exporter import BuildReportExporterFactory
from dockerls.infrastructure.config.settings import Settings
from dockerls.infrastructure.docker.docker_builder import DockerCliBuilder
from dockerls.infrastructure.evidence import EvidenceStore
from dockerls.infrastructure.logging.setup import setup_logging
from dockerls.infrastructure.vault.vault_pusher import VaultPusher
from dockerls.integrations.dockerhub.client import DockerHubClient
from dockerls.integrations.endoflife.checker import EndOfLifeChecker
from dockerls.integrations.registry.hardened import (
    ChainguardRepository,
    DistrolessRepository,
)
from dockerls.integrations.threat_intel.client import ThreatIntelClient
from dockerls.utils.auth import load_credentials
from dockerls.utils.validation import validate_threshold

if TYPE_CHECKING:
    from dockerls.application.services.progress import ScanObserver
    from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface

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


def resolve_tag_limit(limit: int | None) -> int:
    """`--limit` falls back to the configured `max_tags`."""
    s = _settings()
    return validate_threshold(s.max_tags if limit is None else limit, "--limit")


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
        max_attempts=s.retry_max_attempts,
        backoff_base=s.retry_backoff_base,
        tag_ttl_seconds=s.tag_cache_ttl_seconds,
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


def build_hardened_repositories() -> list[ImageRepositoryInterface]:
    """Free, security-hardened catalogues searched alongside Docker Hub."""
    s = _settings()
    if not s.include_hardened_sources:
        return []
    return [
        ChainguardRepository(timeout=s.http_timeout),
        DistrolessRepository(timeout=s.http_timeout),
    ]


async def build_recommend_use_case(
    max_critical: int | None = None,
    max_high: int | None = None,
    max_medium: int | None = None,
    workers: int | None = None,
    observer: ScanObserver | None = None,
    cross_validate: bool | None = None,
    verify_hub_tags: bool | None = None,
    include_hardened: bool | None = None,
) -> RecommendImagesUseCase:
    s = _settings()
    # None means "not given on the command line", so the configured value
    # applies. Previously these carried hard-coded defaults that shadowed
    # Settings entirely, which made DOCKERLS_MAX_MEDIUM and the config file
    # silently do nothing.
    max_critical = validate_threshold(
        s.max_critical if max_critical is None else max_critical, "--max-critical"
    )
    max_high = validate_threshold(s.max_high if max_high is None else max_high, "--max-high")
    max_medium = validate_threshold(
        s.max_medium if max_medium is None else max_medium, "--max-medium"
    )
    workers = validate_threshold(s.workers if workers is None else workers, "--workers")
    if workers < 1:
        raise ValueError("--workers must be at least 1")

    cache = build_cache()
    hub = await build_repository(cache=cache)
    hardened = (
        build_hardened_repositories()
        if (s.include_hardened_sources if include_hardened is None else include_hardened)
        else []
    )
    repo = CompositeImageRepository(hub, hardened, extra_limit=s.hardened_tag_limit)
    evidence = build_evidence_store()
    scanner = await ScannerFactory.create(
        timeout=s.scanner_timeout,
        workers=workers,
        cache_dir=s.trivy_cache_dir,
        evidence=evidence,
    )
    eol = EndOfLifeChecker(
        timeout=s.http_timeout,
        max_attempts=s.retry_max_attempts,
        backoff_base=s.retry_backoff_base,
    )

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
        cross_validator=CrossValidator(secondary, workers=s.cross_validate_workers),
        evidence=evidence,
        verify_hub_tags=s.verify_hub_tags if verify_hub_tags is None else verify_hub_tags,
        log_file=current_log_file(),
        cache_ttl_seconds=s.cache_ttl_seconds,
    )


def build_hardening_level(override: str = "") -> HardeningLevel:
    """`--hardening-level` falls back to the configured level."""
    raw = (override or _settings().hardening_level).strip().lower()
    try:
        return HardeningLevel(raw)
    except ValueError as e:
        levels = ", ".join(level.value for level in HardeningLevel)
        raise ValueError(f"Unknown hardening level '{raw}'. Choose one of: {levels}") from e


def build_dockerfile_analyzer(
    hardening_level: HardeningLevel,
    skip_rules: list[str] | None = None,
) -> AnalyzeDockerfileUseCase:
    validator = OwaspDockerfileValidator(
        hardening_level=hardening_level,
        suggester=HardeningSuggester(),
        skip_rules=skip_rules,
    )
    return AnalyzeDockerfileUseCase(validator=validator)


def build_template_generator(hardening_level: HardeningLevel) -> GenerateHardenedDockerfileUseCase:
    """The generator validates what it wrote, so `templates generate` can
    state the template's score instead of asserting that it is hardened."""
    return GenerateHardenedDockerfileUseCase(
        validator=OwaspDockerfileValidator(hardening_level=hardening_level)
    )


def build_vault_pusher(root_override: str = "") -> VaultPusher | None:
    s = _settings()
    root = Path(root_override) if root_override else s.vault_root
    if root is None:
        return None
    return VaultPusher(root)


async def build_build_use_case(
    hardening_level: HardeningLevel,
    skip_rules: list[str] | None = None,
    scan: bool = True,
    sbom_formats: tuple[str, ...] = (),
    vault_root: str = "",
    cross_validate: bool | None = None,
) -> BuildImageUseCase:
    """Assemble `dockerls build`.

    Scanners are only constructed when a scan was actually requested:
    `--validate-only` and `--no-scan` must not pay for a Trivy DB check
    they will never use.
    """
    s = _settings()
    evidence = build_evidence_store()

    scanner = None
    secondary = None
    if scan:
        scanner = await ScannerFactory.create(
            timeout=s.scanner_timeout,
            cache_dir=s.trivy_cache_dir,
            evidence=evidence,
        )
        if s.cross_validate if cross_validate is None else cross_validate:
            secondary = await ScannerFactory.create_secondary(
                scanner, timeout=s.scanner_timeout, evidence=evidence
            )

    return BuildImageUseCase(
        analyzer=build_dockerfile_analyzer(hardening_level, skip_rules),
        builder=DockerCliBuilder(timeout=s.build_timeout),
        report_generator=BuildReportGenerator(),
        scanner=scanner,
        secondary_scanner=secondary,
        exporter_factory=BuildReportExporterFactory,
        vault=build_vault_pusher(vault_root),
        sbom_dir=s.sbom_dir,
        report_dir=s.build_report_dir,
        sbom_formats=sbom_formats or ("cyclonedx",),
        log_file=str(current_log_file() or ""),
    )


def build_defaults() -> tuple[str, bool, bool]:
    """Configured `dockerls build` defaults the CLI applies when the
    corresponding flag was not given: (fail_on, buildkit, generate_sbom)."""
    s = _settings()
    return s.build_fail_on, s.buildkit, s.generate_sbom


async def build_analyze_use_case() -> AnalyzeImageUseCase:
    s = _settings()
    repo = await build_repository()
    scanner = await ScannerFactory.create(timeout=s.scanner_timeout)
    eol = EndOfLifeChecker(
        timeout=s.http_timeout,
        max_attempts=s.retry_max_attempts,
        backoff_base=s.retry_backoff_base,
    )
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
    """`search` goes through its use case like every other command, so the
    CLI never reaches past the application layer into a repository."""
    return SearchImagesUseCase(repository=await build_repository())
