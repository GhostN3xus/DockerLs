from __future__ import annotations

import re
import sys
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from loguru import Record

_KV_SECRET_PATTERN = re.compile(r"(token|password|secret|key|auth)(\s*[=:]\s*)\S+", re.IGNORECASE)
_BEARER_PATTERN = re.compile(r"Bearer\s+\S+", re.IGNORECASE)
_BASIC_PATTERN = re.compile(r"Basic\s+\S+", re.IGNORECASE)


def _mask_secrets(message: str) -> str:
    # Never echo any part of the secret value itself -- only the key name
    # and separator (e.g. "token=") are non-sensitive and kept for context.
    result = _KV_SECRET_PATTERN.sub(lambda m: f"{m.group(1)}{m.group(2)}***MASKED***", message)
    result = _BEARER_PATTERN.sub("Bearer ***MASKED***", result)
    result = _BASIC_PATTERN.sub("Basic ***MASKED***", result)
    return result


def _log_filter(record: Record) -> bool:
    record["message"] = _mask_secrets(record["message"])
    return True


def setup_logging(level: str = "INFO") -> None:
    logger.remove()
    logger.add(
        sys.stderr,
        level=level.upper(),
        format=(
            "<level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - {message}"
        ),
        filter=_log_filter,
    )
