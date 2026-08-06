from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest

from dockerls.utils.auth import clear_credentials, load_credentials, store_credentials


@pytest.fixture
def fake_keyring(monkeypatch):
    fake = types.ModuleType("keyring")
    fake.set_password = MagicMock()
    fake.get_password = MagicMock(return_value=None)
    fake.delete_password = MagicMock()
    monkeypatch.setitem(sys.modules, "keyring", fake)
    return fake


class TestStoreCredentials:
    def test_store_success(self, fake_keyring):
        assert store_credentials("user", "token") is True
        fake_keyring.set_password.assert_any_call("dockerls", "username", "user")
        fake_keyring.set_password.assert_any_call("dockerls", "token", "token")

    def test_store_failure_returns_false(self, monkeypatch):
        fake = types.ModuleType("keyring")

        def _raise(*a, **k):
            raise RuntimeError("no backend")

        fake.set_password = _raise
        monkeypatch.setitem(sys.modules, "keyring", fake)
        assert store_credentials("user", "token") is False


class TestLoadCredentials:
    def test_load_returns_stored_values(self, fake_keyring):
        fake_keyring.get_password = MagicMock(side_effect=["user", "token"])
        username, token = load_credentials()
        assert username == "user"
        assert token == "token"

    def test_load_failure_returns_empty(self, monkeypatch):
        fake = types.ModuleType("keyring")

        def _raise(*a, **k):
            raise RuntimeError("no backend")

        fake.get_password = _raise
        monkeypatch.setitem(sys.modules, "keyring", fake)
        assert load_credentials() == ("", "")


class TestClearCredentials:
    def test_clear_success(self, fake_keyring):
        assert clear_credentials() is True

    def test_clear_failure_returns_false(self, monkeypatch):
        fake = types.ModuleType("keyring")

        def _raise(*a, **k):
            raise RuntimeError("no backend")

        fake.delete_password = _raise
        monkeypatch.setitem(sys.modules, "keyring", fake)
        assert clear_credentials() is False
