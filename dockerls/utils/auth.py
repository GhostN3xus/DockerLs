from __future__ import annotations

import contextlib
import os
import sys
from typing import TYPE_CHECKING, TypeVar

from loguru import logger

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

# A keyring backend is arbitrary third-party code loaded at call time. It can
# fail in ways that are *not* `Exception`: the `cryptography` backend used by
# SecretService is a Rust extension, and a broken install raises
# `pyo3_runtime.PanicException`, which derives straight from `BaseException`.
# Catching only `Exception` there let a broken keyring take down every command
# that merely tries to *read* optional credentials. Credentials are optional
# enrichment, never a reason to abort, so the guard is widened -- while still
# letting the two BaseExceptions that must always propagate through.
_MUST_PROPAGATE = (KeyboardInterrupt, SystemExit, MemoryError)

T = TypeVar("T")


@contextlib.contextmanager
def _quiet_stderr() -> Iterator[None]:
    """Silence writes to file descriptor 2 for the duration of the block.

    Catching the failure is not enough to keep the terminal clean. Keyring's
    backend discovery writes its diagnostics *below* Python: the missing
    `_cffi_backend` import and pyo3's `thread '<unnamed>' panicked at ...`
    banner are emitted straight to fd 2 by the C and Rust runtimes before
    any Python exception exists to be caught. On a machine with no keyring
    backend -- a container or a CI runner, which is where this tool mostly
    runs -- that noise printed ahead of the results of *every* command and
    read like a crash.

    Only the raw fd is redirected, and only around the keyring call. The
    reason for the failure is not lost: it is logged (through loguru's own
    sinks) after the fd is restored.

    Degrades to a no-op if stderr has no real file descriptor, which is the
    case under pytest's capture and in some embedded runners.
    """
    try:
        fd = sys.stderr.fileno()
    except (AttributeError, OSError, ValueError):
        yield
        return

    sys.stderr.flush()
    saved = os.dup(fd)
    devnull = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(devnull, fd)
        yield
    finally:
        sys.stderr.flush()
        os.dup2(saved, fd)
        os.close(saved)
        os.close(devnull)


def _guarded(operation: str, action: Callable[[], T], default: T, *, level: str = "DEBUG") -> T:
    """Run a keyring `action`, returning `default` if the backend misbehaves."""
    try:
        with _quiet_stderr():
            return action()
    except _MUST_PROPAGATE:
        raise
    except BaseException as e:
        logger.log(level, f"{operation}: {type(e).__name__}: {e}")
        return default


def store_credentials(username: str, token: str) -> bool:
    def action() -> bool:
        import keyring

        keyring.set_password("dockerls", "username", username)
        keyring.set_password("dockerls", "token", token)
        return True

    # A failed *store* is worth a warning: the user asked for it explicitly.
    return _guarded("Keyring storage failed", action, False, level="WARNING")


def load_credentials() -> tuple[str, str]:
    def action() -> tuple[str, str]:
        import keyring

        username = keyring.get_password("dockerls", "username") or ""
        token = keyring.get_password("dockerls", "token") or ""
        return username, token

    return _guarded("Keyring unavailable, continuing anonymously", action, ("", ""))


def clear_credentials() -> bool:
    def action() -> bool:
        import keyring

        keyring.delete_password("dockerls", "username")
        keyring.delete_password("dockerls", "token")
        return True

    return _guarded("Keyring deletion failed", action, False)
