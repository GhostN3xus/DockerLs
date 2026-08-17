from __future__ import annotations

import contextlib
import os
import stat
import sys
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

# Stub scanner Python scripts. They emit the same JSON shapes the real tools do,
# so the pipeline under test is real end to end -- only the vulnerability
# database lookup is replaced, which is what makes the timing budget
# meaningful rather than a measure of network weather.
TRIVY_PY = """import sys, os, time, json
cache = ""
download = False
last = ""
args = sys.argv[1:]
i = 0
while i < len(args):
    if args[i] == "--cache-dir" and i + 1 < len(args):
        cache = args[i+1]
        i += 2
    elif args[i] == "--download-db-only":
        download = True
        i += 1
    else:
        last = args[i]
        i += 1

if download:
    if cache:
        db_dir = os.path.join(cache, "db")
        os.makedirs(db_dir, exist_ok=True)
        with open(os.path.join(db_dir, "trivy.db"), "w", encoding="utf-8") as f:
            f.write("db")
        with open(os.path.join(db_dir, "metadata.json"), "w", encoding="utf-8") as f:
            f.write("{}")
    sys.exit(0)

delay = float(os.environ.get("DOCKERLS_TEST_TRIVY_DELAY", "0"))
if delay > 0:
    time.sleep(delay)

dirty = os.environ.get("DOCKERLS_TEST_TRIVY_DIRTY_MATCH", "")
if dirty and dirty in last:
    print(json.dumps({"Results":[{"Vulnerabilities":[
        {"VulnerabilityID":"CVE-2026-1","Severity":"HIGH","PkgName":"libx",
         "InstalledVersion":"1.0","FixedVersion":"1.1","Title":"stub"},
        {"VulnerabilityID":"CVE-2026-2","Severity":"HIGH","PkgName":"liby",
         "InstalledVersion":"1.0","FixedVersion":"1.1","Title":"stub"}
    ]}]}))
    sys.exit(0)

print(json.dumps({"Results":[{"Vulnerabilities":[]}]}))
"""

GRYPE_PY = """import sys, os, time, json
stamp = os.environ.get("DOCKERLS_TEST_GRYPE_STAMP", "")
args = sys.argv[1:]
if args and args[0] == "db":
    delay = float(os.environ.get("DOCKERLS_TEST_GRYPE_DB_DELAY", "0"))
    if delay > 0:
        time.sleep(delay)
    if stamp:
        with open(stamp, "w", encoding="utf-8") as f:
            f.write("updated")
    sys.exit(0)

if stamp and not os.path.exists(stamp) and os.environ.get("GRYPE_DB_AUTO_UPDATE") != "false":
    delay = float(os.environ.get("DOCKERLS_TEST_GRYPE_DB_DELAY", "0"))
    if delay > 0:
        time.sleep(delay)

delay = float(os.environ.get("DOCKERLS_TEST_GRYPE_DELAY", "0"))
if delay > 0:
    time.sleep(delay)

print(json.dumps({"matches":[]}))
"""

TRIVY_SH = """#!/bin/sh
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
if [ -n "$DOCKERLS_TEST_TRIVY_DIRTY_MATCH" ] && \\
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

GRYPE_SH = """#!/bin/sh
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


def _write_stub(path: Path, py_code: str, sh_code: str) -> None:
    # 1. Shell script for Linux / POSIX
    path.write_text(sh_code, encoding="utf-8")
    with contextlib.suppress(OSError):
        path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    # 2. Python helper script
    py_path = path.with_suffix(".py")
    py_path.write_text(py_code, encoding="utf-8")

    # 3. Windows Batch and CMD wrappers
    bat_path = path.with_name(f"{path.name}.bat")
    bat_path.write_text(f'@echo off\n"{sys.executable}" "{py_path}" %*\n', encoding="utf-8")
    cmd_path = path.with_name(f"{path.name}.cmd")
    cmd_path.write_text(f'@echo off\n"{sys.executable}" "{py_path}" %*\n', encoding="utf-8")


@pytest.fixture
def scanner_stubs(tmp_path, monkeypatch):
    """Put fake `trivy` and `grype` on PATH and return their timing knobs."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _write_stub(bindir / "trivy", TRIVY_PY, TRIVY_SH)
    _write_stub(bindir / "grype", GRYPE_PY, GRYPE_SH)

    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("DOCKERLS_TEST_TRIVY_DELAY", "0.05")
    monkeypatch.setenv("DOCKERLS_TEST_GRYPE_DELAY", "0.05")
    monkeypatch.setenv("DOCKERLS_TEST_GRYPE_DB_DELAY", "0.30")
    monkeypatch.setenv("DOCKERLS_TEST_GRYPE_STAMP", str(tmp_path / "grype-db-updated"))
    monkeypatch.setenv("DOCKERLS_TEST_TRIVY_DIRTY_MATCH", "")
    return tmp_path
