from __future__ import annotations

from loguru import logger


def store_credentials(username: str, token: str) -> bool:
    try:
        import keyring

        keyring.set_password("dockerls", "username", username)
        keyring.set_password("dockerls", "token", token)
        return True
    except Exception as e:
        logger.warning(f"Keyring storage failed: {e}")
        return False


def load_credentials() -> tuple[str, str]:
    try:
        import keyring

        username = keyring.get_password("dockerls", "username") or ""
        token = keyring.get_password("dockerls", "token") or ""
        return username, token
    except Exception:
        return "", ""


def clear_credentials() -> bool:
    try:
        import keyring

        keyring.delete_password("dockerls", "username")
        keyring.delete_password("dockerls", "token")
        return True
    except Exception:
        return False
