"""Fixtures shared by the scanner integration tests.

The scanners resolve `trivy`/`grype` to an absolute path before executing
them, so they no longer run on a machine that does not have the tools
installed -- which is the point, but it also means these tests would depend
on the host having them. The lookup is stubbed instead: the subprocess call
itself is already mocked, so nothing is executed either way.
"""

from __future__ import annotations

import pytest

# What `shutil.which` is made to return, and therefore what argv[0] is.
STUB_BIN_DIR = "/usr/local/bin"


def stub_path(name: str) -> str:
    return f"{STUB_BIN_DIR}/{name}"


@pytest.fixture(autouse=True)
def _stub_executable_lookup(monkeypatch):
    monkeypatch.setattr("shutil.which", stub_path)
