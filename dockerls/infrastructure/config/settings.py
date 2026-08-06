from __future__ import annotations

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


def _default_config_path() -> Path:
    """~/.config/dockerls/config.toml (or $XDG_CONFIG_HOME/dockerls/config.toml)."""
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg_config) if xdg_config else Path.home() / ".config"
    return base / "dockerls" / "config.toml"


class Settings(BaseSettings):
    """Configuration resolved, highest priority first, from: constructor
    kwargs -> environment variables -> ~/.config/dockerls/config.toml ->
    field defaults. DOCKERHUB_USERNAME/DOCKERHUB_TOKEN/NVD_API_KEY keep
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
    max_tags: int = 100
    workers: int = 10
    max_critical: int = 0
    max_high: int = 0
    max_medium: int = 5
    dockerhub_username: str = Field(default="", validation_alias="DOCKERHUB_USERNAME")
    dockerhub_token: str = Field(default="", validation_alias="DOCKERHUB_TOKEN")
    log_level: str = "INFO"
    scanner_timeout: int = 300
    http_timeout: int = 30
    retry_max_attempts: int = 3
    retry_backoff_base: float = 2.0
    enable_threat_intel: bool = True
    nvd_api_key: str = Field(default="", validation_alias="NVD_API_KEY")

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
