"""Provenance for a build: who built what, from which commit, when.

Every lookup here is best-effort. A build outside a git checkout, or on a
machine with no `git`, must still produce a report -- it just produces one
that says "unknown" instead of inventing a commit.
"""

from __future__ import annotations

import asyncio
import getpass
import os
import socket
from datetime import UTC, datetime

from loguru import logger

from dockerls import __version__
from dockerls.application.dto.build import BuildMetadata

GIT_TIMEOUT = 10


async def collect_build_metadata(
    context_path: str,
    docker_version: str = "",
    buildkit: bool = True,
) -> BuildMetadata:
    sha, branch = await asyncio.gather(
        _git(context_path, "rev-parse", "HEAD"),
        _git(context_path, "rev-parse", "--abbrev-ref", "HEAD"),
    )
    return BuildMetadata(
        timestamp=datetime.now(tz=UTC).isoformat(),
        git_sha=sha,
        git_branch=branch,
        built_by=_identity(),
        docker_version=docker_version,
        buildkit=buildkit,
        dockerls_version=__version__,
    )


def _identity() -> str:
    """`user@host`, falling back through the ways each half can be
    unavailable (no passwd entry in a container, no resolvable hostname)."""
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - getuser raises bare Exception on some platforms
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    try:
        host = socket.gethostname() or "unknown"
    except OSError:
        host = "unknown"
    return f"{user}@{host}"


async def _git(cwd: str, *args: str) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(  # noqa: S603
            "git",
            "-C",
            cwd,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=GIT_TIMEOUT)
    except (TimeoutError, OSError) as e:
        logger.debug(f"git {' '.join(args)} unavailable: {e}")
        return ""
    if proc.returncode != 0:
        return ""
    return stdout.decode(errors="replace").strip()
