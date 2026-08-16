"""Run an external scanner and guarantee the child process is reaped.

`asyncio.wait_for(proc.communicate(), timeout=...)` cancels the *await*, not
the process. On timeout the coroutine raises and the caller returns a
`TIMEOUT` scan result, while the `trivy` or `grype` process it started keeps
running: still downloading, still matching, still holding the exclusive
BoltDB lock on its Trivy cache directory -- which is precisely the
contention `TrivyCachePool` exists to eliminate. With `--workers 10` a run
that trips its timeout could leave ten scanners behind, outliving the CLI
that spawned them and slowing down the next invocation that tries to take
the same lock.

The same applies to cancellation: Ctrl-C unwinds the event loop, and without
an explicit kill the children survive it.

`run_capture` closes both holes. Every path out -- success, timeout,
cancellation, or an error raised inside the body -- goes through a
`finally` that terminates the process and *waits* for it, so the process
table is clean before the caller sees the outcome.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

from loguru import logger

if TYPE_CHECKING:
    from collections.abc import Mapping

# How long a signalled scanner is given to exit on its own before SIGKILL.
# Trivy and Grype flush and exit promptly; this only bounds the pathological
# case of a process ignoring SIGTERM.
_TERMINATE_GRACE_SECONDS = 5.0


async def run_capture(
    argv: list[str],
    *,
    timeout: float,
    env: Mapping[str, str] | None = None,
) -> tuple[int, bytes, bytes]:
    """Run `argv`, returning ``(returncode, stdout, stderr)``.

    `argv[0]` must already be an absolute path (see
    `dockerls.utils.executables.resolve_executable`); nothing here goes
    through a shell, and the arguments are passed as a list, so no quoting
    or escaping is involved at any point.

    Raises `TimeoutError` if the process does not finish within `timeout`.
    In that case -- and on cancellation -- the process is killed and reaped
    before the exception propagates.
    """
    proc = await asyncio.create_subprocess_exec(  # noqa: S603 -- argv list, no shell
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    finally:
        await _reap(proc, argv[0])
    return proc.returncode or 0, stdout, stderr


async def _reap(proc: asyncio.subprocess.Process, name: str) -> None:
    """Terminate `proc` if it is still running, then wait for it.

    A no-op on the normal path: `communicate()` already returned, so
    `returncode` is set. Shielded from cancellation so that a Ctrl-C
    arriving *during* cleanup cannot skip the kill it is here to perform.
    """
    if proc.returncode is not None:
        return
    logger.warning(f"Killing unfinished subprocess {name} (pid {proc.pid})")
    with contextlib.suppress(ProcessLookupError):
        proc.terminate()
    try:
        await asyncio.shield(asyncio.wait_for(proc.wait(), timeout=_TERMINATE_GRACE_SECONDS))
    except (TimeoutError, asyncio.CancelledError):
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.shield(proc.wait())
