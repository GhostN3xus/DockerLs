from __future__ import annotations

import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from loguru import Record

MASK = "***MASKED***"

# Key names that introduce a credential, in any casing or word shape
# ("apiKey", "api_key", "API-KEY", "dockerhub_token", "senha").
_SECRET_KEY = r"[\w.-]*(?:token|password|passwd|senha|secret|api[-_]?key|credential|auth)[\w.-]*"  # noqa: S105

# A quoted key/value pair, as it appears in JSON or a dict repr:
#   "token": "value"      'apiKey' : 'value'      "auth": {"token": "value"}
# The quote between the key and the separator is exactly what the previous
# pattern could not cross, which left every JSON-shaped log line in clear.
_QUOTED_KV = re.compile(
    rf"""(?P<prefix>["']?{_SECRET_KEY}["']?\s*[:=]\s*)(?P<quote>["'])(?P<value>(?:\\.|[^"'\\])*)(?P=quote)""",
    re.IGNORECASE,
)

# An unquoted key/value pair: token=abc, senha: abc, x-api-key: abc.
_BARE_KV = re.compile(
    rf"(?P<prefix>\b{_SECRET_KEY}\s*[=:]\s*)(?P<value>[^\s,;&\"'}}\]]+)", re.IGNORECASE
)

# Authorization schemes.
_SCHEME = re.compile(
    r"\b(?P<scheme>Bearer|Basic|Token|Digest)\s+(?P<value>[^\s,;\"'=:][^\s,;\"']*)",
    re.IGNORECASE,
)

# Credentials embedded in a URL: https://user:secret@host
_URL_USERINFO = re.compile(r"(?P<prefix>://[^/\s:@]+:)(?P<value>[^@/\s]+)(?P<at>@)")

# curl-style inline credentials: -u user:secret, --user user:secret
_CURL_USER = re.compile(r"(?P<prefix>(?:-u|--user)\s+[^\s:]+:)(?P<value>\S+)")

# Credential formats that are self-identifying, so they are redacted even
# when they appear with no key to introduce them -- a bare token inside a
# list or an exception message has no "token=" in front of it.
_KNOWN_SECRET_VALUE = re.compile(
    r"""
      \bdckr_pat_[A-Za-z0-9_-]{8,}                          # Docker Hub PAT
    | \bgh[pousr]_[A-Za-z0-9]{20,}                           # GitHub token
    | \beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]+  # JWT
    | \bAKIA[0-9A-Z]{16}\b                                   # AWS access key id
    | \bxox[baprs]-[A-Za-z0-9-]{10,}                          # Slack token
    """,
    re.VERBOSE,
)

# multipart/form-data, where the value sits on its own line after a blank
# line rather than next to the key.
_MULTIPART = re.compile(
    rf"""(?P<prefix>name=["']{_SECRET_KEY}["'][^\n]*\r?\n\r?\n)(?P<value>[^\r\n]+)""",
    re.IGNORECASE,
)

_FILE_FORMAT = "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} - {message}"
_CONSOLE_FORMAT = (
    "<level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - {message}"
)


def _mask_secrets(message: str) -> str:
    """Redact credentials from a log line in every shape they arrive in.

    Only the key name and separator (e.g. `token=`) are kept, never any part
    of the value. Over-masking a benign line is an acceptable cost; leaking
    a token into a log file is not, so the key patterns are deliberately
    broad.

    Order matters: scheme patterns run before the key/value ones, because
    in `auth: Bearer <token>` a key/value match would consume only the word
    `Bearer` and stop, leaving the credential in the clear.
    """
    result = _SCHEME.sub(lambda m: f"{m.group('scheme')} {MASK}", message)
    result = _URL_USERINFO.sub(lambda m: f"{m.group('prefix')}{MASK}{m.group('at')}", result)
    result = _CURL_USER.sub(lambda m: f"{m.group('prefix')}{MASK}", result)
    result = _MULTIPART.sub(lambda m: f"{m.group('prefix')}{MASK}", result)
    result = _QUOTED_KV.sub(
        lambda m: f"{m.group('prefix')}{m.group('quote')}{MASK}{m.group('quote')}", result
    )
    result = _BARE_KV.sub(lambda m: f"{m.group('prefix')}{MASK}", result)
    # Last: catch self-identifying credential formats that appeared with no
    # key in front of them for any of the patterns above to anchor on.
    result = _KNOWN_SECRET_VALUE.sub(MASK, result)
    return result


def _log_filter(record: Record) -> bool:
    record["message"] = _mask_secrets(record["message"])
    return True


def _resolve_log_file(log_dir: Path) -> Path | None:
    """Return a writable `<log_dir>/dockerls_<timestamp>.log`, or None when
    no directory in the fallback chain can be created."""
    stamp = datetime.now(tz=UTC).strftime("%Y-%m-%d_%H-%M-%S")
    candidates = [log_dir]
    fallback = Path.home() / ".cache" / "dockerls" / "logs"
    if fallback != log_dir:
        candidates.append(fallback)

    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            path = candidate / f"dockerls_{stamp}.log"
            path.touch()
        except OSError:
            continue
        return path
    return None


def setup_logging(
    level: str = "INFO",
    log_dir: Path | None = None,
    console: bool = False,
) -> Path | None:
    """Route diagnostics to a rotating log file instead of the terminal.

    The CLI owns the terminal (Rich progress bars and tables), so loguru's
    default stderr sink is always removed: scanner failures, retries and
    debug chatter would otherwise interleave with -- and corrupt -- the
    progress display. Set `console=True` (``--verbose``) to opt back into
    stderr logging on top of the file sink.

    Returns the active log file path so callers can point the user at it.
    """
    logger.remove()

    log_file = _resolve_log_file(log_dir or Path("logs"))
    if log_file is not None:
        logger.add(
            log_file,
            level=level.upper(),
            format=_FILE_FORMAT,
            filter=_log_filter,
            enqueue=True,
            retention=20,
            encoding="utf-8",
        )

    if console or log_file is None:
        logger.add(
            sys.stderr,
            level=level.upper(),
            format=_CONSOLE_FORMAT,
            filter=_log_filter,
        )

    return log_file
