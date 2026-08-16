"""Release the resources a use case borrowed, without letting cleanup lose a result.

Scanners hold temporary Trivy cache directories; repositories hold an
`httpx.AsyncClient` whose connection pool is kept alive for the whole run so
requests can reuse it. Both therefore have to be handed back, and the only
place that knows when a run is over is the use case that started it.

Everything here is duck-typed on `close()` for the same reason the rest of
the pipeline is: a test double, a repository with no pool, and a scanner
that owns nothing all need to work without implementing anything.
"""

from __future__ import annotations

from typing import Any

from loguru import logger


async def close_quietly(*resources: Any) -> None:
    """Await `close()` on each resource that has one.

    A failure to clean up is logged and swallowed. It must never replace the
    result the caller is about to return: an unclosed socket is a smaller
    problem than a completed scan being reported as an error, which is what
    letting the exception escape a `finally` would do.
    """
    for resource in resources:
        if resource is None:
            continue
        close = getattr(resource, "close", None)
        if not callable(close):
            continue
        try:
            await close()
        except Exception as e:  # pragma: no cover - cleanup must not mask results
            logger.warning(f"Cleanup failed for {type(resource).__name__}: {e}")


def sources_of(repository: Any) -> list[Any]:
    """The individual image sources behind a repository.

    `CompositeImageRepository` exposes a real list of them; anything else --
    a single client, or a test double whose attributes are auto-created --
    is the one source it is.
    """
    sources = getattr(repository, "sources", None)
    if isinstance(sources, list | tuple):
        return list(sources)
    return [repository]
