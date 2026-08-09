from __future__ import annotations

from loguru import logger

# A keyring backend is arbitrary third-party code loaded at call time. It can
# fail in ways that are *not* `Exception`: the `cryptography` backend used by
# SecretService is a Rust extension, and a broken install raises
# `pyo3_runtime.PanicException`, which derives straight from `BaseException`.
# Catching only `Exception` there let a broken keyring take down every command
# that merely tries to *read* optional credentials. Credentials are optional
# enrichment, never a reason to abort, so the guard is widened -- while still
# letting the two BaseExceptions that must always propagate through.
_MUST_PROPAGATE = (KeyboardInterrupt, SystemExit, MemoryError)


def store_credentials(username: str, token: str) -> bool:
    try:
        import keyring

        keyring.set_password("dockerls", "username", username)
        keyring.set_password("dockerls", "token", token)
        return True
    except _MUST_PROPAGATE:
        raise
    except BaseException as e:
        logger.warning(f"Keyring storage failed: {type(e).__name__}: {e}")
        return False


def load_credentials() -> tuple[str, str]:
    try:
        import keyring

        username = keyring.get_password("dockerls", "username") or ""
        token = keyring.get_password("dockerls", "token") or ""
        return username, token
    except _MUST_PROPAGATE:
        raise
    except BaseException as e:
        logger.debug(f"Keyring unavailable, continuing anonymously: {type(e).__name__}: {e}")
        return "", ""


def clear_credentials() -> bool:
    try:
        import keyring

        keyring.delete_password("dockerls", "username")
        keyring.delete_password("dockerls", "token")
        return True
    except _MUST_PROPAGATE:
        raise
    except BaseException as e:
        logger.debug(f"Keyring deletion failed: {type(e).__name__}: {e}")
        return False
