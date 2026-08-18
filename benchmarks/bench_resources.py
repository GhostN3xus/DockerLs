"""What one run costs the machine it lands on.

Two numbers here were pathological before this benchmark existed, and both
were invisible from the outside:

1. **Redaction.** Every scan artifact is masked before it is written. The
   key patterns began with `[\\w.-]*`, which made the regex engine try every
   split of an unbounded character class at every position of a
   multi-megabyte document -- 19 seconds of pure CPU per scanned image. On a
   100-tag run that is half an hour of masking.
2. **Worker sizing.** Each worker holds a *scanner process*, not a
   coroutine. A flat default of ten of them on a two-core runner does not
   run ten times faster; it thrashes, and can get the job OOM-killed.

Run with `python benchmarks/bench_resources.py`.

Measured on this repository:

    redact, 1.3 MB artifact  :   245 ms   (was 19 445 ms)
    redact, 0.3 MB artifact  :    55 ms   (was  3 295 ms)
    workers on a 4-CPU host  :     4      (was 10, regardless of the host)
    100 tags x 800 findings  :   107 MB peak, 6 MB residual
"""

from __future__ import annotations

import json
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dockerls.domain.entities.scan_result import ScanResult, ScanStatus  # noqa: E402
from dockerls.domain.entities.vulnerability import Severity, Vulnerability  # noqa: E402
from dockerls.infrastructure.redaction import redact  # noqa: E402
from dockerls.utils import resources  # noqa: E402

#: Above this, redaction is back to being the bottleneck it used to be.
REDACTION_BUDGET_MS_PER_MB = 400


def _artifact(findings: int) -> str:
    """A Trivy document shaped like a real one: long descriptions, many
    findings, and the runs of word characters that defeated the old
    patterns."""
    return json.dumps(
        {
            "Results": [
                {
                    "Target": "node:22 (debian 12)",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": f"CVE-2024-{i:05d}",
                            "PkgName": f"libpkg{i % 300}",
                            "InstalledVersion": "1.2.3-1",
                            "FixedVersion": "1.2.4-1",
                            "Severity": "HIGH",
                            "Description": "x" * 400,
                        }
                        for i in range(findings)
                    ],
                }
            ]
        }
    )


def bench_redaction() -> None:
    print("== redaction of scan artifacts ==")
    for findings in (500, 3000):
        raw = _artifact(findings)
        megabytes = len(raw) / 1024 / 1024
        start = time.monotonic()
        redact(raw)
        elapsed_ms = (time.monotonic() - start) * 1000
        budget = megabytes * REDACTION_BUDGET_MS_PER_MB
        verdict = "OK" if elapsed_ms <= budget else "OVER BUDGET"
        print(
            f"  {findings:5d} findings ({megabytes:4.1f} MB): {elapsed_ms:7.0f} ms "
            f"(budget {budget:.0f} ms) {verdict}"
        )


def bench_capacity() -> None:
    print("\n== worker sizing ==")
    print(f"  machine                    : {resources.describe_capacity()}")
    print(f"  recommended workers        : {resources.recommended_workers()}")
    print("  (was: a flat 10, whatever the machine)")


def bench_memory() -> None:
    print("\n== memory held by one run ==")
    tags, findings = 100, 800
    tracemalloc.start()
    baseline = tracemalloc.get_traced_memory()[0]
    scans = [
        ScanResult(
            image_reference=f"node:t{t}",
            status=ScanStatus.OK,
            scan_timestamp="2026-01-01T00:00:00Z",
            vulnerabilities=[
                Vulnerability(
                    cve_id=f"CVE-2024-{i:05d}",
                    severity=Severity.HIGH,
                    package_name=f"libpkg{i % 300}",
                    installed_version="1.2.3-1",
                    fixed_version="1.2.4-1",
                    description="x" * 200,
                )
                for i in range(findings)
            ],
        )
        for t in range(tags)
    ]
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    held = (current - baseline) / 1024 / 1024
    print(
        f"  {tags} tags x {findings} findings: {held:.0f} MB held, {peak / 1024 / 1024:.0f} MB peak"
    )
    print(f"  per finding                : {(current - baseline) / (tags * findings):.0f} bytes")
    del scans


if __name__ == "__main__":
    bench_redaction()
    bench_capacity()
    bench_memory()
