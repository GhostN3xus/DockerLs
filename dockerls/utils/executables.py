"""Absolute-path resolution for the external tools DockerLs shells out to.

Invoking `docker`, `trivy` or `grype` by bare name hands the choice of binary
to `$PATH`, so any writable directory earlier in the search order decides what
runs. That is PATH hijacking -- the same class of finding this tool reports on
other people's images -- and a security scanner is a particularly good thing to
hijack, since its verdict is what a pipeline trusts.

Every subprocess call resolves the name here first and invokes the absolute
path that comes back, or fails with a message naming the tool that is missing.
"""

from __future__ import annotations

import shutil


class ExecutableNotFoundError(RuntimeError):
    """A required external tool is not installed, or not on `$PATH`."""

    def __init__(self, name: str) -> None:
        super().__init__(
            f"'{name}' was not found on PATH. Install it (see `dockerls doctor`) "
            f"and make sure it is on the PATH of the process running dockerls."
        )
        self.name = name


def resolve_executable(name: str) -> str:
    """Return the absolute path of `name`, or raise `ExecutableNotFoundError`.

    The absolute path is what gets executed: resolving and then invoking the
    bare name again would reintroduce the lookup this function exists to pin
    down.
    """
    path = shutil.which(name)
    if path is None:
        raise ExecutableNotFoundError(name)
    return path
