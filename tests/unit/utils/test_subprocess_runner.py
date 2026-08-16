"""A scanner that outruns its timeout must not outlive the run.

`asyncio.wait_for(proc.communicate(), ...)` cancels the await, not the
process. Before `run_capture`, a timed-out `trivy image` kept running with
the exclusive BoltDB lock on its cache directory still held -- the exact
contention `TrivyCachePool` exists to remove -- and survived the CLI that
started it. With `--workers 10`, one slow registry could leave ten of them
behind.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys

import pytest

from dockerls.utils.subprocess_runner import run_capture

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX process semantics"
)

_SLEEPER = [sys.executable, "-c", "import time; time.sleep(30)"]
_QUICK = [sys.executable, "-c", "import sys; sys.stdout.write('hi'); sys.exit(3)"]


def _alive(pid: int) -> bool:
    """True while `pid` exists and has not been reaped."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover - not reachable for own children
        return True
    return True


class TestNormalCompletion:
    async def test_returns_code_stdout_and_stderr(self):
        code, stdout, stderr = await run_capture(_QUICK, timeout=30)
        assert code == 3
        assert stdout == b"hi"
        assert stderr == b""

    async def test_passes_environment_through(self):
        argv = [sys.executable, "-c", "import os,sys; sys.stdout.write(os.environ['MARKER'])"]
        env = {**os.environ, "MARKER": "from-env"}
        _, stdout, _ = await run_capture(argv, timeout=30, env=env)
        assert stdout == b"from-env"


class TestTimeoutKillsTheChild:
    async def test_timeout_raises(self):
        with pytest.raises(TimeoutError):
            await run_capture(_SLEEPER, timeout=0.2)

    async def test_child_is_dead_by_the_time_the_error_surfaces(self, monkeypatch):
        """The kill happens in a `finally`, so the process is already reaped
        when the caller sees TimeoutError -- not merely scheduled to die."""
        seen: dict[str, int] = {}
        real = asyncio.create_subprocess_exec

        async def spy(*args, **kwargs):
            proc = await real(*args, **kwargs)
            seen["pid"] = proc.pid
            return proc

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)

        with pytest.raises(TimeoutError):
            await run_capture(_SLEEPER, timeout=0.2)

        assert "pid" in seen
        assert not _alive(seen["pid"]), "scanner process outlived its timeout"


class TestCancellationKillsTheChild:
    async def test_ctrl_c_does_not_leave_a_scanner_running(self, monkeypatch):
        seen: dict[str, int] = {}
        real = asyncio.create_subprocess_exec

        async def spy(*args, **kwargs):
            proc = await real(*args, **kwargs)
            seen["pid"] = proc.pid
            return proc

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)

        task = asyncio.create_task(run_capture(_SLEEPER, timeout=30))
        while "pid" not in seen:
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert not _alive(seen["pid"]), "scanner process outlived a cancelled run"


class TestUncooperativeChild:
    async def test_a_process_ignoring_sigterm_is_killed(self, monkeypatch):
        """The grace period is bounded: SIGTERM first, SIGKILL after."""
        monkeypatch.setattr(
            "dockerls.utils.subprocess_runner._TERMINATE_GRACE_SECONDS", 0.3
        )
        argv = [
            sys.executable,
            "-c",
            f"import signal,time; signal.signal({int(signal.SIGTERM)}, signal.SIG_IGN); "
            "time.sleep(30)",
        ]
        seen: dict[str, int] = {}
        real = asyncio.create_subprocess_exec

        async def spy(*args, **kwargs):
            proc = await real(*args, **kwargs)
            seen["pid"] = proc.pid
            return proc

        monkeypatch.setattr(asyncio, "create_subprocess_exec", spy)

        with pytest.raises(TimeoutError):
            await run_capture(argv, timeout=0.3)

        assert not _alive(seen["pid"]), "a SIGTERM-ignoring scanner was not SIGKILLed"


class TestScannersUseIt:
    """The two scanners must go through the runner, not raw
    `create_subprocess_exec` -- otherwise the guarantee above is bypassed."""

    @pytest.mark.parametrize(
        "module",
        [
            "dockerls/integrations/trivy/scanner.py",
            "dockerls/integrations/grype/scanner.py",
        ],
    )
    def test_no_raw_subprocess_calls_remain(self, module):
        from pathlib import Path

        source = Path(module).read_text(encoding="utf-8")
        assert "create_subprocess_exec" not in source
        assert "run_capture" in source
