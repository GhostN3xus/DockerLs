"""Every setting the README documents must reach the real execution path.

Audit finding: `Settings` declared max_tags, workers, max_critical,
max_high, max_medium, cache_ttl_seconds, retry_* and nvd_api_key, and the
README documented `DOCKERLS_<SETTING>` / `config.toml` as the way to change
them -- but the CLI carried its own hard-coded `typer.Option` defaults that
shadowed `Settings` entirely. `DOCKERLS_MAX_MEDIUM=10` and the documented
`max_tags = 200` config example silently did nothing.

These tests fail if a setting stops being read on the real path again.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from dockerls.application.dto.analysis import AnalysisResult
from dockerls.cli import dependencies
from dockerls.cli.app import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _clear_settings_cache():
    """Settings is lru_cached; each test needs its own environment applied."""
    dependencies._settings.cache_clear()
    yield
    dependencies._settings.cache_clear()


def _capture_use_case_args(monkeypatch, *cli_args, env=None):
    """Run `recommend` and return the kwargs the use case was built with."""
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)

    captured: dict = {}
    executed: dict = {}

    async def fake_build(**kwargs):
        captured.update(kwargs)
        uc = AsyncMock()

        async def execute(image, limit=None):
            executed["limit"] = limit
            return AnalysisResult(query=image, total_tags_scanned=0, baseline_met=False)

        uc.execute = execute
        return uc

    with patch("dockerls.cli.commands.recommend.build_recommend_use_case", fake_build):
        result = runner.invoke(app, ["recommend", "node", "--no-progress", *cli_args])
    return captured, executed, result


def _resolved(monkeypatch, *cli_args, env=None):
    """Resolve the thresholds the use case would actually be constructed with."""
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    dependencies._settings.cache_clear()

    captured: dict = {}

    class _Recorder:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    with (
        patch("dockerls.cli.dependencies.RecommendImagesUseCase", _Recorder),
        patch("dockerls.cli.dependencies.build_repository", AsyncMock()),
        patch("dockerls.cli.dependencies.ScannerFactory.create", AsyncMock()),
        patch("dockerls.cli.dependencies.ScannerFactory.create_secondary", AsyncMock()),
    ):
        import asyncio

        asyncio.run(dependencies.build_recommend_use_case(**dict(cli_args)))
    return captured


class TestThresholdsComeFromSettings:
    def test_env_var_changes_max_medium(self, monkeypatch):
        captured = _resolved(monkeypatch, env={"DOCKERLS_MAX_MEDIUM": "42"})
        assert captured["max_medium"] == 42

    def test_env_var_changes_max_critical_and_high(self, monkeypatch):
        captured = _resolved(
            monkeypatch, env={"DOCKERLS_MAX_CRITICAL": "3", "DOCKERLS_MAX_HIGH": "7"}
        )
        assert captured["max_critical"] == 3
        assert captured["max_high"] == 7

    def test_env_var_changes_workers(self, monkeypatch):
        captured = _resolved(monkeypatch, env={"DOCKERLS_WORKERS": "25"})
        assert captured["workers"] == 25

    def test_documented_defaults_apply_when_nothing_is_set(self, monkeypatch):
        for var in ("DOCKERLS_MAX_MEDIUM", "DOCKERLS_MAX_CRITICAL", "DOCKERLS_MAX_HIGH"):
            monkeypatch.delenv(var, raising=False)
        captured = _resolved(monkeypatch)
        # Must match the README "Default thresholds" table.
        assert captured["max_critical"] == 0
        assert captured["max_high"] == 0
        assert captured["max_medium"] == 5
        assert captured["workers"] == 10

    def test_cli_flag_still_wins_over_config(self, monkeypatch):
        captured = _resolved(monkeypatch, ("max_medium", 1), env={"DOCKERLS_MAX_MEDIUM": "42"})
        assert captured["max_medium"] == 1


class TestTagLimitComesFromSettings:
    def test_env_var_changes_the_tag_limit(self, monkeypatch):
        """The README's own example is `DOCKERLS_MAX_TAGS=200`."""
        monkeypatch.setenv("DOCKERLS_MAX_TAGS", "200")
        dependencies._settings.cache_clear()
        assert dependencies.resolve_tag_limit(None) == 200

    def test_documented_default_applies(self, monkeypatch):
        monkeypatch.delenv("DOCKERLS_MAX_TAGS", raising=False)
        dependencies._settings.cache_clear()
        assert dependencies.resolve_tag_limit(None) == 100

    def test_cli_flag_wins(self, monkeypatch):
        monkeypatch.setenv("DOCKERLS_MAX_TAGS", "200")
        dependencies._settings.cache_clear()
        assert dependencies.resolve_tag_limit(7) == 7

    def test_limit_reaches_execute(self, monkeypatch):
        _, executed, _ = _capture_use_case_args(monkeypatch, "--limit", "3")
        assert executed["limit"] == 3


class TestThresholdsAreValidated:
    """`validate_threshold` existed in utils but was never called, so
    `--max-critical -5` was accepted silently."""

    @pytest.mark.parametrize("env", [{"DOCKERLS_MAX_CRITICAL": "-5"}, {"DOCKERLS_MAX_HIGH": "-1"}])
    def test_negative_threshold_is_rejected(self, monkeypatch, env):
        with pytest.raises(ValueError, match="non-negative"):
            _resolved(monkeypatch, env=env)

    def test_absurd_threshold_is_rejected(self, monkeypatch):
        with pytest.raises(ValueError, match="maximum"):
            _resolved(monkeypatch, env={"DOCKERLS_MAX_MEDIUM": "999999"})

    def test_zero_workers_is_rejected(self, monkeypatch):
        with pytest.raises(ValueError, match="at least 1"):
            _resolved(monkeypatch, env={"DOCKERLS_WORKERS": "0"})

    def test_negative_limit_is_rejected(self, monkeypatch):
        monkeypatch.delenv("DOCKERLS_MAX_TAGS", raising=False)
        dependencies._settings.cache_clear()
        with pytest.raises(ValueError, match="non-negative"):
            dependencies.resolve_tag_limit(-1)


class TestInvalidConfigIsAUserErrorNotACrash:
    def test_negative_threshold_prints_a_message_not_a_traceback(self, monkeypatch):
        monkeypatch.setenv("DOCKERLS_MAX_CRITICAL", "-5")
        dependencies._settings.cache_clear()
        result = runner.invoke(app, ["recommend", "node", "--no-progress"])

        assert result.exit_code == 1
        assert "Invalid configuration" in result.stdout
        assert "must be non-negative" in result.stdout
        assert "Traceback" not in result.stdout
