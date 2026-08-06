from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

# Stub scanner binaries. They emit the same JSON shapes the real tools do,
# so the pipeline under test is real end to end -- only the vulnerability
# database lookup is replaced, which is what makes the timing budget
# meaningful rather than a measure of network weather.
TRIVY_STUB = """#!/bin/sh
CACHE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --cache-dir) CACHE="$2"; shift 2 ;;
    --download-db-only) DOWNLOAD=1; shift ;;
    *) LAST="$1"; shift ;;
  esac
done
if [ -n "$DOWNLOAD" ]; then
  mkdir -p "$CACHE/db"
  echo db > "$CACHE/db/trivy.db"
  echo '{}' > "$CACHE/db/metadata.json"
  exit 0
fi
sleep "$DOCKERLS_TEST_TRIVY_DELAY"
# Images matching DIRTY_MATCH report findings; everything else is clean.
# Lets a test make hardened images genuinely win on measured vulnerabilities.
if [ -n "$DOCKERLS_TEST_TRIVY_DIRTY_MATCH" ] && \
   [ "${LAST#*$DOCKERLS_TEST_TRIVY_DIRTY_MATCH}" != "$LAST" ]; then
  echo '{"Results":[{"Vulnerabilities":[
    {"VulnerabilityID":"CVE-2026-1","Severity":"HIGH","PkgName":"libx",
     "InstalledVersion":"1.0","FixedVersion":"1.1","Title":"stub"},
    {"VulnerabilityID":"CVE-2026-2","Severity":"HIGH","PkgName":"liby",
     "InstalledVersion":"1.0","FixedVersion":"1.1","Title":"stub"}
  ]}]}'
  exit 0
fi
echo '{"Results":[{"Vulnerabilities":[]}]}'
"""

# Mimics grype's real cost model: a DB freshness round trip on every
# invocation unless `grype db update` has already run.
GRYPE_STUB = """#!/bin/sh
STAMP="$DOCKERLS_TEST_GRYPE_STAMP"
if [ "$1" = "db" ]; then
  sleep "$DOCKERLS_TEST_GRYPE_DB_DELAY"
  touch "$STAMP"
  exit 0
fi
if [ ! -f "$STAMP" ] && [ "$GRYPE_DB_AUTO_UPDATE" != "false" ]; then
  sleep "$DOCKERLS_TEST_GRYPE_DB_DELAY"
fi
sleep "$DOCKERLS_TEST_GRYPE_DELAY"
echo '{"matches":[]}'
"""


def _write_stub(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture
def scanner_stubs(tmp_path, monkeypatch):
    """Put fake `trivy` and `grype` on PATH and return their timing knobs."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_stub(bindir / "trivy", TRIVY_STUB)
    _write_stub(bindir / "grype", GRYPE_STUB)

    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("DOCKERLS_TEST_TRIVY_DELAY", "0.05")
    monkeypatch.setenv("DOCKERLS_TEST_GRYPE_DELAY", "0.05")
    monkeypatch.setenv("DOCKERLS_TEST_GRYPE_DB_DELAY", "0.30")
    monkeypatch.setenv("DOCKERLS_TEST_GRYPE_STAMP", str(tmp_path / "grype-db-updated"))
    monkeypatch.setenv("DOCKERLS_TEST_TRIVY_DIRTY_MATCH", "")
    return tmp_path
