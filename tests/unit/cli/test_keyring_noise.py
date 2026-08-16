"""A broken keyring backend must not print anything.

Catching the failure was never enough. Keyring's backend discovery writes
its diagnostics *below* Python -- the missing `_cffi_backend` import and
pyo3's `thread '<unnamed>' panicked at ...` banner go straight to file
descriptor 2 from the C and Rust runtimes, before any Python exception
exists to catch. On a container or CI runner with no keyring backend (where
this tool mostly runs) that noise printed ahead of the results of every
single command and read like a crash.

These tests run a real subprocess, because that is the only place a raw fd
write is observable: pytest's capture replaces `sys.stderr` with an object
that has no real descriptor, so an in-process test cannot see the bug it is
meant to catch.
"""

from __future__ import annotations

import subprocess  # noqa: S404 - the test *is* about subprocess-visible output
import sys
import textwrap

import pytest

from dockerls.utils.auth import clear_credentials, load_credentials, store_credentials

# A stand-in for the real failure mode: a backend that writes to fd 2 and
# then raises something deriving from BaseException, exactly as pyo3 does.
_NOISY_KEYRING = textwrap.dedent(
    """
    import os, sys, types

    class Panic(BaseException):
        pass

    def _noisy(*args, **kwargs):
        os.write(2, b"thread '<unnamed>' panicked at src/err/mod.rs:788:5\\n")
        raise Panic("Python API call failed")

    fake = types.ModuleType("keyring")
    fake.get_password = _noisy
    fake.set_password = _noisy
    fake.delete_password = _noisy
    sys.modules["keyring"] = fake

    # What every command does first: detach loguru's default stderr sink so
    # the terminal belongs to the results. Without this the script would see
    # loguru's own (correctly filtered) diagnostic line and not the bug.
    from dockerls.cli.dependencies import configure_logging
    configure_logging()

    from dockerls.utils.auth import {call}
    print("RESULT:", {expr})
    """
)


def _run(call: str, expr: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", _NOISY_KEYRING.format(call=call, expr=expr)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


class TestBackendNoiseNeverReachesTheTerminal:
    @pytest.mark.parametrize(
        ("call", "expr", "expected"),
        [
            ("load_credentials", "load_credentials()", "('', '')"),
            ("store_credentials", "store_credentials('u', 't')", "False"),
            ("clear_credentials", "clear_credentials()", "False"),
        ],
    )
    def test_no_panic_banner_on_stderr(self, call, expr, expected):
        result = _run(call, expr)

        assert result.returncode == 0, result.stderr
        assert f"RESULT: {expected}" in result.stdout
        assert "panicked" not in result.stderr
        assert result.stderr.strip() == "", f"keyring noise leaked: {result.stderr!r}"


class TestFailureIsStillHandled:
    """Silencing the descriptor must not silence the *outcome*: a broken
    backend still degrades to anonymous access rather than aborting."""

    def test_load_degrades_to_anonymous(self, monkeypatch):
        import sys as _sys
        import types

        fake = types.ModuleType("keyring")

        def boom(*args, **kwargs):
            raise RuntimeError("backend exploded")

        fake.get_password = boom
        monkeypatch.setitem(_sys.modules, "keyring", fake)

        assert load_credentials() == ("", "")

    def test_store_reports_failure(self, monkeypatch):
        import sys as _sys
        import types

        fake = types.ModuleType("keyring")

        def boom(*args, **kwargs):
            raise RuntimeError("backend exploded")

        fake.set_password = boom
        monkeypatch.setitem(_sys.modules, "keyring", fake)

        assert store_credentials("u", "t") is False

    def test_clear_reports_failure(self, monkeypatch):
        import sys as _sys
        import types

        fake = types.ModuleType("keyring")

        def boom(*args, **kwargs):
            raise RuntimeError("backend exploded")

        fake.delete_password = boom
        monkeypatch.setitem(_sys.modules, "keyring", fake)

        assert clear_credentials() is False


class TestInterruptsStillPropagate:
    """Ctrl-C during a keyring read must remain a Ctrl-C. Widening the catch
    to BaseException is what makes this worth pinning down."""

    @pytest.mark.parametrize("exc", [KeyboardInterrupt, SystemExit, MemoryError])
    def test_must_propagate_exceptions_are_not_swallowed(self, monkeypatch, exc):
        import sys as _sys
        import types

        fake = types.ModuleType("keyring")

        def boom(*args, **kwargs):
            raise exc()

        fake.get_password = boom
        monkeypatch.setitem(_sys.modules, "keyring", fake)

        with pytest.raises(exc):
            load_credentials()


class TestStderrIsRestored:
    """The redirect is scoped: whatever the command prints afterwards must
    still reach the terminal."""

    def test_later_writes_still_appear(self):
        script = textwrap.dedent(
            """
            import os, sys, types
            fake = types.ModuleType("keyring")
            def boom(*a, **k):
                os.write(2, b"noise\\n")
                raise RuntimeError("x")
            fake.get_password = boom
            sys.modules["keyring"] = fake

            from dockerls.utils.auth import load_credentials
            load_credentials()
            os.write(2, b"AFTER\\n")
            """
        )
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "noise" not in result.stderr
        assert "AFTER" in result.stderr
