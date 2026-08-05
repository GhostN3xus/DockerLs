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
