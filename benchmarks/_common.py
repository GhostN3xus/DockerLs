"""Shared plumbing for the pipeline benchmarks: environment, statistics, output.

Two kinds of benchmark live in this directory and they are never mixed in one
table:

* **simulated** (`bench_pipeline.py`, `bench_profiles.py`): the real
  application code -- use cases, measurement service, layered store, scoring --
  wired to in-process fakes that sleep for a configurable time instead of
  contacting a registry or running a scanner. They measure *orchestration*:
  how many scans a scenario needs, how well work overlaps, what the caches
  save. The latencies are inputs, printed with every result; they are not
  measurements of any real registry or scanner.
* **real** (`bench_real.py`): the installed CLI against real registries and a
  real Trivy. They measure wall-clock time end to end, on whatever machine and
  network they are run on, and say so.

Run from the repository root: the simulated ones reuse the test fakes.
"""

from __future__ import annotations

import json
import math
import os
import platform
import statistics
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _git(*args: str) -> str:
    try:
        return subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", *args],  # noqa: S607
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def environment(**extra: str) -> dict[str, str]:
    """Where and with what the numbers were produced."""
    from dockerls import __version__

    return {
        "date": datetime.now(tz=UTC).isoformat(timespec="seconds"),
        "dockerls": __version__,
        "git_commit": _git("rev-parse", "--short", "HEAD"),
        "git_dirty": "yes" if _git("status", "--porcelain") else "no",
        "python": platform.python_version(),
        "os": f"{platform.system()} {platform.release()}",
        "machine": platform.machine(),
        "cpus": str(os.cpu_count()),
        **extra,
    }


def percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile; with few samples p95 is simply the maximum,
    which is what the table then says (`n` is always printed)."""
    if not values:
        return math.nan
    ordered = sorted(values)
    rank = max(1, math.ceil(q * len(ordered)))
    return ordered[rank - 1]


@dataclass
class Sample:
    seconds: float
    counters: dict[str, float] = field(default_factory=dict)


@dataclass
class Row:
    scenario: str
    kind: str  # "simulated" | "real"
    n: int
    median_s: float
    p95_s: float
    min_s: float
    max_s: float
    counters: dict[str, float]
    note: str = ""


def summarize(scenario: str, kind: str, samples: list[Sample], note: str = "") -> Row:
    seconds = [s.seconds for s in samples]
    keys = sorted({k for s in samples for k in s.counters})
    return Row(
        scenario=scenario,
        kind=kind,
        n=len(samples),
        median_s=statistics.median(seconds),
        p95_s=percentile(seconds, 0.95),
        min_s=min(seconds),
        max_s=max(seconds),
        counters={
            k: statistics.median([s.counters[k] for s in samples if k in s.counters]) for k in keys
        },
        note=note,
    )


def render_table(rows: list[Row]) -> str:
    keys = sorted({k for r in rows for k in r.counters})
    header = ["scenario", "n", "median s", "p95 s", *keys]
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    for r in rows:
        cells = [r.scenario, str(r.n), f"{r.median_s:.3f}", f"{r.p95_s:.3f}"]
        cells += [f"{r.counters[k]:g}" if k in r.counters else "-" for k in keys]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def emit(
    title: str,
    env: dict[str, str],
    parameters: dict[str, object],
    rows: list[Row],
    json_path: str | None,
) -> None:
    print(f"# {title}\n")
    print("Environment: " + ", ".join(f"{k}={v}" for k, v in env.items()))
    print("Parameters:  " + ", ".join(f"{k}={v}" for k, v in parameters.items()) + "\n")
    print(render_table(rows))
    for r in rows:
        if r.note:
            print(f"\n- {r.scenario}: {r.note}")
    if json_path:
        Path(json_path).write_text(
            json.dumps(
                {
                    "title": title,
                    "environment": env,
                    "parameters": parameters,
                    "rows": [asdict(r) for r in rows],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nJSON written to {json_path}")
