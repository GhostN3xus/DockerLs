"""`docker build` driven through the CLI, the same way scanners are driven.

The Docker SDK is deliberately not a dependency: this package already
shells out to trivy and grype, the CLI is what every user and CI runner
already has authenticated, and the SDK adds a second, differently-versioned
opinion about how to talk to the daemon.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any

from loguru import logger

from dockerls.application.dto.build import BuildResult, LayerInfo
from dockerls.domain.interfaces.image_builder import ImageBuilderInterface
from dockerls.infrastructure.docker.buildkit import (
    BuildArgumentError,
    build_command,
    build_environment,
    validate_tag,
)

if TYPE_CHECKING:
    from dockerls.application.dto.build import BuildOptions

# Enough of the engine's output to explain a failure without pasting a
# multi-megabyte build log into a JSON report.
LOG_TAIL_LINES = 40
DEFAULT_BUILD_TIMEOUT = 1800
DEFAULT_PUSH_TIMEOUT = 900


class DockerCliBuilder(ImageBuilderInterface):
    def __init__(self, timeout: int = DEFAULT_BUILD_TIMEOUT):
        self._timeout = timeout

    async def is_available(self) -> bool:
        """True only when the daemon answers -- `docker` being on PATH says
        nothing about whether a build can actually run."""
        code, _, _ = await self._run(["docker", "version", "--format", "{{.Server.Version}}"], 20)
        return code == 0

    async def server_version(self) -> str:
        code, out, _ = await self._run(["docker", "version", "--format", "{{.Server.Version}}"], 20)
        return out.strip() if code == 0 else ""

    async def build(self, options: BuildOptions) -> BuildResult:
        try:
            cmd = build_command(options)
        except BuildArgumentError as e:
            return BuildResult(success=False, tag=options.tag, error=str(e))

        env = build_environment(options)
        logger.info(f"Building {options.tag} from {options.dockerfile_path}")
        # The argv is logged, never the environment: `--secret id=x,env=Y`
        # names the variable, and the log file must not gain its value.
        logger.debug(f"docker argv: {' '.join(cmd)}")

        started = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(  # noqa: S603
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=env,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self._timeout)
            returncode = proc.returncode
        except TimeoutError:
            return BuildResult(
                success=False,
                tag=options.tag,
                duration_seconds=round(time.monotonic() - started, 1),
                error=f"Build exceeded {self._timeout}s timeout",
            )
        except OSError as e:
            return BuildResult(success=False, tag=options.tag, error=f"Could not run docker: {e}")

        duration = round(time.monotonic() - started, 1)
        output = stdout.decode(errors="replace")
        for line in output.splitlines():
            logger.debug(f"docker: {line}")

        if returncode != 0:
            return BuildResult(
                success=False,
                tag=options.tag,
                duration_seconds=duration,
                error=f"docker build exited with code {returncode}",
                log_tail=_tail(output),
                buildkit_used=options.buildkit,
            )

        image_id, size, layers = await self._inspect(options.tag)
        return BuildResult(
            success=True,
            tag=options.tag,
            image_id=image_id,
            size_bytes=size,
            layers=layers,
            duration_seconds=duration,
            log_tail=_tail(output),
            buildkit_used=options.buildkit,
        )

    async def push(self, tag: str) -> tuple[bool, str]:
        try:
            safe_tag = validate_tag(tag)
        except BuildArgumentError as e:
            return False, str(e)
        code, out, err = await self._run(["docker", "push", "--", safe_tag], DEFAULT_PUSH_TIMEOUT)
        if code == 0:
            return True, _tail(out, lines=5)
        return False, _tail(err or out)

    async def _inspect(self, tag: str) -> tuple[str, int, list[LayerInfo]]:
        """Read back the image the build just produced.

        Failures here are non-fatal: a report missing its layer breakdown is
        still a valid report, and refusing the build over it would discard a
        successful, already-scanned image.
        """
        code, out, err = await self._run(["docker", "image", "inspect", "--", tag], 60)
        if code != 0:
            logger.warning(f"Could not inspect {tag}: {err.strip()[:200]}")
            return "", 0, []
        try:
            data: list[dict[str, Any]] = json.loads(out)
        except json.JSONDecodeError as e:
            logger.warning(f"Could not parse `docker image inspect` output for {tag}: {e}")
            return "", 0, []
        if not data:
            return "", 0, []

        image = data[0]
        image_id = str(image.get("Id", ""))
        size = int(image.get("Size", 0) or 0)
        digests = image.get("RootFS", {}).get("Layers", []) or []
        history = [h for h in image.get("History", []) or [] if not h.get("empty_layer")]
        layers = [
            LayerInfo(
                digest=str(digest),
                created_by=str(history[i].get("created_by", ""))[:200] if i < len(history) else "",
            )
            for i, digest in enumerate(digests)
        ]
        return image_id, size, layers

    async def _run(self, cmd: list[str], timeout: int) -> tuple[int, str, str]:
        try:
            proc = await asyncio.create_subprocess_exec(  # noqa: S603
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            return 124, "", f"`{cmd[0]} {cmd[1]}` exceeded {timeout}s"
        except OSError as e:
            return 127, "", str(e)
        return (
            proc.returncode or 0,
            stdout.decode(errors="replace"),
            stderr.decode(errors="replace"),
        )


def _tail(text: str, lines: int = LOG_TAIL_LINES) -> str:
    return "\n".join(text.splitlines()[-lines:])
