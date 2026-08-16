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

    def test_runtime_artifacts_default_to_xdg_state_home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
        s = Settings()
        assert s.log_dir == tmp_path / "state" / "dockerls" / "logs"
        assert s.evidence_dir == tmp_path / "state" / "dockerls" / "scans"

    def test_runtime_artifact_dirs_can_be_overridden(self, tmp_path, monkeypatch):
        monkeypatch.setenv("DOCKERLS_LOG_DIR", str(tmp_path / "project-logs"))
        monkeypatch.setenv("DOCKERLS_EVIDENCE_DIR", str(tmp_path / "project-scans"))
        s = Settings()
        assert s.log_dir == tmp_path / "project-logs"
        assert s.evidence_dir == tmp_path / "project-scans"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("DOCKERHUB_USERNAME", "testuser")
        monkeypatch.setenv("DOCKERHUB_TOKEN", "testtoken")
        s = Settings()
        assert s.dockerhub_username == "testuser"
        assert s.dockerhub_token == "testtoken"

    def test_threat_intel_enabled_by_default(self):
        s = Settings()
        assert s.enable_threat_intel is True

    def test_threat_intel_disable_env_var(self, monkeypatch):
        monkeypatch.setenv("DOCKERLS_DISABLE_THREAT_INTEL", "1")
        s = Settings()
        assert s.enable_threat_intel is False

    def test_dockerls_prefixed_env_var_override(self, monkeypatch):
        monkeypatch.setenv("DOCKERLS_MAX_TAGS", "55")
        monkeypatch.setenv("DOCKERLS_WORKERS", "3")
        s = Settings()
        assert s.max_tags == 55
        assert s.workers == 3

    def test_toml_config_file_loaded(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.toml"
        config_file.write_text("max_tags = 42\nworkers = 7\n")
        monkeypatch.setitem(Settings.model_config, "toml_file", config_file)
        s = Settings()
        assert s.max_tags == 42
        assert s.workers == 7

    def test_env_var_takes_priority_over_toml(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.toml"
        config_file.write_text("max_tags = 42\n")
        monkeypatch.setitem(Settings.model_config, "toml_file", config_file)
        monkeypatch.setenv("DOCKERLS_MAX_TAGS", "99")
        s = Settings()
        assert s.max_tags == 99

    def test_missing_toml_file_uses_defaults(self, tmp_path, monkeypatch):
        monkeypatch.setitem(Settings.model_config, "toml_file", tmp_path / "nonexistent.toml")
        s = Settings()
        assert s.max_tags == 100
