from __future__ import annotations

import re
import sys

from loguru import logger

_SENSITIVE_PATTERNS = [
    re.compile(r"(token|password|secret|key|auth)\s*[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"Bearer\s+\S+", re.IGNORECASE),
    re.compile(r"Basic\s+\S+", re.IGNORECASE),
]


def _mask_secrets(message: str) -> str:
    result = message
    for pattern in _SENSITIVE_PATTERNS:
        result = pattern.sub(lambda m: m.group(0)[:10] + "***MASKED***", result)
    return result


def _log_filter(record: dict) -> bool:
    record["message"] = _mask_secrets(record["message"])
    return True


def setup_logging(level: str = "INFO") -> None:
    logger.remove()
    logger.add(
        sys.stderr,
        level=level.upper(),
        format="<level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - {message}",
        filter=_log_filter,
    )
