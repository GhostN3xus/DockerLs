from dockerls.cli.dependencies import _settings


class TestSettingsSingleton:
    def test_settings_is_cached(self):
        first = _settings()
        second = _settings()
        assert first is second
