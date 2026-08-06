from __future__ import annotations

from tenacity import AsyncRetrying, stop_after_attempt, wait_exponential

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BACKOFF_BASE = 2.0
MAX_BACKOFF_SECONDS = 10.0


def retry_policy(
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    backoff_base: float = DEFAULT_BACKOFF_BASE,
) -> AsyncRetrying:
    """Build a retry policy from configuration.

    A `@retry(...)` decorator is evaluated once at import time, which is why
    `retry_max_attempts` and `retry_backoff_base` could be declared as
    settings and documented while having no possible effect. Building the
    policy per call is what lets configuration actually reach it.

    `reraise=True` so callers still see the original exception rather than
    tenacity's RetryError wrapper -- the existing error handling in the
    clients catches httpx errors by type.
    """
    return AsyncRetrying(
        stop=stop_after_attempt(max(1, max_attempts)),
        wait=wait_exponential(
            multiplier=1, exp_base=max(1.1, backoff_base), max=MAX_BACKOFF_SECONDS
        ),
        reraise=True,
    )
