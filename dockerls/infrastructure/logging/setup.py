from __future__ import annotations

import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from loguru import Record

_KV_SECRET_PATTERN = re.compile(r"(token|password|secret|key|auth)(\s*[=:]\s*)\S+", re.IGNORECASE)
_BEARER_PATTERN = re.compile(r"Bearer\s+\S+", re.IGNORECASE)
_BASIC_PATTERN = re.compile(r"Basic\s+\S+", re.IGNORECASE)

_FILE_FORMAT = "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} - {message}"
_CONSOLE_FORMAT = (
    "<level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - {message}"
)


def _mask_secrets(message: str) -> str:
    # Never echo any part of the secret value itself -- only the key name
    # and separator (e.g. "token=") are non-sensitive and kept for context.
    #
    # Scheme patterns run *first*. In "auth: Bearer <token>" the key-value
    # pattern's \S+ would otherwise consume only the word "Bearer" and stop,
    # leaving the actual credential in the clear.
    result = _BEARER_PATTERN.sub("Bearer ***MASKED***", message)
    result = _BASIC_PATTERN.sub("Basic ***MASKED***", result)
    result = _KV_SECRET_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}***MASKED***", result)
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
