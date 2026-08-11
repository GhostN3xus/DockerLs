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


class TestKeyringBackendCrashes:
    """A keyring backend is arbitrary third-party code, and part of it is
    native. The `cryptography` backend behind SecretService raises
    `pyo3_runtime.PanicException` when its Rust extension is broken -- and
    that derives from `BaseException`, not `Exception`, so the original
    `except Exception` did not catch it. Reading optional credentials then
    took down every command that touched them.
    """

    class _Panic(BaseException):
        """Stands in for pyo3_runtime.PanicException: BaseException, not
        Exception."""

    def _panicking_keyring(self, monkeypatch):
        fake = types.ModuleType("keyring")
        fake.get_password = MagicMock(side_effect=self._Panic("Python API call failed"))
        fake.set_password = MagicMock(side_effect=self._Panic("Python API call failed"))
        fake.delete_password = MagicMock(side_effect=self._Panic("Python API call failed"))
        monkeypatch.setitem(sys.modules, "keyring", fake)

    def test_load_survives_a_base_exception(self, monkeypatch):
        self._panicking_keyring(monkeypatch)
        assert load_credentials() == ("", "")

    def test_store_survives_a_base_exception(self, monkeypatch):
        self._panicking_keyring(monkeypatch)
        assert store_credentials("user", "token") is False

    def test_clear_survives_a_base_exception(self, monkeypatch):
        self._panicking_keyring(monkeypatch)
        assert clear_credentials() is False

    @pytest.mark.parametrize("exc", [KeyboardInterrupt, SystemExit])
    def test_interrupts_still_propagate(self, monkeypatch, exc):
        """Widening the guard must not swallow Ctrl-C."""
        fake = types.ModuleType("keyring")
        fake.get_password = MagicMock(side_effect=exc())
        monkeypatch.setitem(sys.modules, "keyring", fake)

        with pytest.raises(exc):
            load_credentials()
