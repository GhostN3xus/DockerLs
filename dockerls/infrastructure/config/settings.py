from __future__ import annotations

import contextlib
import os
from pathlib import Path

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)


def _default_cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "dockerls"
    return Path.home() / ".cache" / "dockerls"


def _default_log_dir() -> Path:
    return Path("logs")


def _default_evidence_dir() -> Path:
    return Path(".dockerls") / "scans"


def _default_report_dir() -> Path:
    return Path(".dockerls") / "reports"


def _default_sbom_dir() -> Path:
    return Path(".dockerls") / "sboms"


def _default_config_path() -> Path:
    """~/.config/dockerls/config.toml (or $XDG_CONFIG_HOME/dockerls/config.toml)."""
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg_config) if xdg_config else Path.home() / ".config"
    return base / "dockerls" / "config.toml"


class Settings(BaseSettings):
    """Configuration resolved, highest priority first, from: constructor
    kwargs -> environment variables -> ~/.config/dockerls/config.toml ->
    field defaults. DOCKERHUB_USERNAME and DOCKERHUB_TOKEN keep
    their historical unprefixed env var names for backward compatibility;
    every other setting is DOCKERLS_<FIELD_NAME>.
    """

    model_config = SettingsConfigDict(
        env_prefix="DOCKERLS_",
        toml_file=_default_config_path(),
        extra="ignore",
    )

    cache_dir: Path = Field(default_factory=_default_cache_dir)
    cache_ttl_seconds: int = 86400
    # Tag existence is cached separately and more briefly: a tag
    # disappearing matters sooner than a score going slightly stale.
    tag_cache_ttl_seconds: int = 6 * 3600
    max_tags: int = 100
    workers: int = 10
    max_critical: int = 0
    max_high: int = 0
    max_medium: int = 5
    dockerhub_username: str = Field(default="", validation_alias="DOCKERHUB_USERNAME")
    dockerhub_token: str = Field(default="", validation_alias="DOCKERHUB_TOKEN")
    log_level: str = "INFO"
    # Diagnostics go here, never to the terminal (see setup_logging).
    log_dir: Path = Field(default_factory=_default_log_dir)
    # Raw scanner JSON, kept so every displayed score is auditable.
    evidence_dir: Path = Field(default_factory=_default_evidence_dir)
    # Trivy's own cache root; the per-worker cache pool is built next to it.
    trivy_cache_dir: Path | None = None
    # Re-scan the top candidates with the secondary scanner and flag
    # material disagreements instead of showing an undisputed score.
    cross_validate: bool = True
    # Confirm each recommended tag really exists on Docker Hub.
    verify_hub_tags: bool = True
    # Concurrent secondary scans during cross-validation.
    cross_validate_workers: int = 5
    # Search free hardened catalogues (Chainguard, Distroless) alongside
    # Docker Hub, so a hardened image can win on measured vulnerabilities.
    include_hardened_sources: bool = True
    # Tags pulled per hardened source; these catalogues are small and their
    # listings are unordered, so a wide fetch buys nothing.
    hardened_tag_limit: int = 10
    scanner_timeout: int = 300
    # -- `dockerls build` -------------------------------------------------
    # Which rule severities are allowed to stop a build: strict adds
    # MEDIUM, relaxed drops everything but CRITICAL. The findings reported
    # are identical at every level.
    hardening_level: str = "standard"
    # A cold multi-stage build with a compile step routinely runs longer
    # than a scan, so this is deliberately not scanner_timeout.
    build_timeout: int = 1800
    # Scan severity at or above which `dockerls build` exits non-zero.
    build_fail_on: str = "critical"
    buildkit: bool = True
    build_report_dir: Path = Field(default_factory=_default_report_dir)
    sbom_dir: Path = Field(default_factory=_default_sbom_dir)
    generate_sbom: bool = True
    # Root of the Obsidian/DevSecOps notes vault that `--vault-push` writes
    # into. Unset means `--vault-push` has nowhere to go and says so.
    vault_root: Path | None = None
    http_timeout: int = 30
    retry_max_attempts: int = 3
    retry_backoff_base: float = 2.0
    enable_threat_intel: bool = True

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            TomlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )

    def model_post_init(self, __context: object) -> None:
        # Legacy opt-out flag from before the DOCKERLS_ env prefix was
        # introduced; keep honoring it alongside DOCKERLS_ENABLE_THREAT_INTEL.
        if os.environ.get("DOCKERLS_DISABLE_THREAT_INTEL"):
            self.enable_threat_intel = False

    @property
    def db_path(self) -> Path:
        return self.cache_dir / "cache.db"

    def ensure_dirs(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        # Log, evidence, report and SBOM dirs are best-effort: a read-only
        # working directory must degrade (setup_logging falls back to the
        # cache dir, artefact writing is skipped) rather than abort the
        # command.
        for path in (self.log_dir, self.evidence_dir, self.build_report_dir, self.sbom_dir):
            with contextlib.suppress(OSError):
                path.mkdir(parents=True, exist_ok=True)
