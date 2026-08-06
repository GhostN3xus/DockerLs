from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field


def _default_cache_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "dockerls"
    return Path.home() / ".cache" / "dockerls"


class Settings(BaseModel):
    cache_dir: Path = Field(default_factory=_default_cache_dir)
    cache_ttl_seconds: int = 86400
    max_tags: int = 100
    workers: int = 10
    max_critical: int = 0
    max_high: int = 0
    max_medium: int = 5
    dockerhub_username: str = ""
    dockerhub_token: str = ""
    log_level: str = "INFO"
    scanner_timeout: int = 300
    http_timeout: int = 30
    retry_max_attempts: int = 3
    retry_backoff_base: float = 2.0
    enable_threat_intel: bool = True
    nvd_api_key: str = ""

    def model_post_init(self, __context: object) -> None:
        if not self.dockerhub_username:
            self.dockerhub_username = os.environ.get("DOCKERHUB_USERNAME", "")
        if not self.dockerhub_token:
            self.dockerhub_token = os.environ.get("DOCKERHUB_TOKEN", "")
        if not self.nvd_api_key:
            self.nvd_api_key = os.environ.get("NVD_API_KEY", "")
        if os.environ.get("DOCKERLS_DISABLE_THREAT_INTEL"):
            self.enable_threat_intel = False

    @property
    def db_path(self) -> Path:
        return self.cache_dir / "cache.db"

    def ensure_dirs(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
