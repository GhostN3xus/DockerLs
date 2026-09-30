"""Keep the test run out of the developer's real state and cache directories.

`Settings` resolves its log, evidence, saved-run and cache directories from
`XDG_STATE_HOME` / `XDG_CACHE_HOME` when they are set. Pointing both at a
throw-away directory *before anything imports the settings* means running the
suite never writes logs, cached scans or saved runs into the real
`~/.local/state/dockerls` or `~/.cache/dockerls`.
"""

from __future__ import annotations

import os
import shutil
import tempfile

_SANDBOX = tempfile.mkdtemp(prefix="dockerls-tests-")
os.environ.setdefault("XDG_STATE_HOME", os.path.join(_SANDBOX, "state"))
os.environ.setdefault("XDG_CACHE_HOME", os.path.join(_SANDBOX, "cache"))


def pytest_sessionfinish(session, exitstatus):  # noqa: ARG001 - pytest hook signature
    shutil.rmtree(_SANDBOX, ignore_errors=True)
