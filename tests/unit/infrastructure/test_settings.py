import os
from pathlib import Path

from dockerls.infrastructure.config.settings import Settings


class TestSettings:
    def test_defaults(self):
        s = Settings()
        assert s.max_tags == 100
        assert s.workers == 10
        assert s.max_critical == 0
        assert s.cache_ttl_seconds == 86400

    def test_db_path(self):
        s = Settings()
        assert s.db_path.name == "cache.db"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("DOCKERHUB_USERNAME", "testuser")
        monkeypatch.setenv("DOCKERHUB_TOKEN", "testtoken")
        s = Settings()
        assert s.dockerhub_username == "testuser"
        assert s.dockerhub_token == "testtoken"

    def test_nvd_api_key_env_override(self, monkeypatch):
        monkeypatch.setenv("NVD_API_KEY", "my-key")
        s = Settings()
        assert s.nvd_api_key == "my-key"

    def test_threat_intel_enabled_by_default(self):
        s = Settings()
        assert s.enable_threat_intel is True

    def test_threat_intel_disable_env_var(self, monkeypatch):
        monkeypatch.setenv("DOCKERLS_DISABLE_THREAT_INTEL", "1")
        s = Settings()
        assert s.enable_threat_intel is False
