"""How much of this machine DockerLs may actually use.

Concurrency here is not the usual "how many coroutines" question. Each
worker slot holds a **scanner process**: `trivy image` reads a multi-hundred
megabyte vulnerability database, unpacks image layers and matches packages,
using a full core and hundreds of megabytes of RSS while it does. Ten of
them at once on a two-core CI runner does not go ten times faster -- it goes
slower, evicts the page cache, and can get the whole job OOM-killed.

The default was a flat `workers = 10`, chosen with no reference to the
machine. This module replaces the guess with a measurement, and it is
deliberately **container-aware**: inside Docker or Kubernetes,
`os.cpu_count()` reports the host's cores while the cgroup allows a
fraction of one. A tool whose whole purpose is analysing containers is
routinely run inside one, so reading the host's numbers is not a small
inaccuracy -- it is the common case, and it is where the oversubscription
hurts most.

Nothing here is a hard limit on what the operator may ask for. An explicit
`--workers` is still honoured: the point is that the *default* should fit
the machine it lands on, and that asking for more than the machine has
should say so out loud.
"""

from __future__ import annotations

import os
from pathlib import Path

from loguru import logger

#: Memory one scanner process should be assumed to need. Trivy's resident
#: set while matching a large image sits in the hundreds of megabytes; this
#: is the conservative end, because the cost of underestimating it is an
#: OOM kill and the cost of overestimating it is one fewer parallel scan.
SCANNER_MEMORY_BYTES = 768 * 1024 * 1024

#: Never derive fewer than this. One worker is always possible, and a
#: machine that reports something absurd should still make progress.
MIN_RECOMMENDED = 1

#: Never derive more than this, however large the machine. Past this point
#: the bottleneck is the registry and the disk, not the CPU, and every extra
#: process is another few hundred megabytes for no throughput.
MAX_RECOMMENDED = 16

_CGROUP_V2_CPU = Path("/sys/fs/cgroup/cpu.max")
_CGROUP_V2_MEMORY = Path("/sys/fs/cgroup/memory.max")
_CGROUP_V1_QUOTA = Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
_CGROUP_V1_PERIOD = Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
_CGROUP_V1_MEMORY = Path("/sys/fs/cgroup/memory/memory.limit_in_bytes")
_MEMINFO = Path("/proc/meminfo")


def cpu_capacity() -> float:
    """Cores this process may actually use, honouring cgroup quota.

    Three sources, narrowest wins: the cgroup CPU quota (what a container
    is allowed), the CPU affinity mask (what a taskset or a scheduler
    policy permits), and the machine's core count. A quota of 0.5 cores
    returns 0.5, not 1 -- the caller decides how to round, and rounding up
    to 1 at the bottom is the caller's floor, not a fact about the machine.
    """
    candidates: list[float] = []

    try:
        candidates.append(float(len(os.sched_getaffinity(0))))
    except (AttributeError, OSError):
        count = os.cpu_count()
        if count:
            candidates.append(float(count))

    quota = _cgroup_cpu_quota()
    if quota is not None:
        candidates.append(quota)

    return min(candidates) if candidates else 1.0


def available_memory_bytes() -> int | None:
    """Memory this process can count on, or None when it cannot be read.

    `MemAvailable` rather than `MemFree`: the kernel's own estimate of what
    can be allocated without swapping, which is the number that decides
    whether starting another scanner is survivable. A cgroup limit, when
    present and lower, wins -- that is the ceiling the OOM killer uses.
    """
    values = [v for v in (_meminfo_available(), _cgroup_memory_limit()) if v is not None]
    return min(values) if values else None


def recommended_workers() -> int:
    """How many scanner processes this machine should run at once.

    The minimum of what the CPU allows and what memory allows, clamped.
    Both terms matter and they fail differently: too many for the CPU makes
    the run slower, too many for the memory makes it die.
    """
    by_cpu = max(MIN_RECOMMENDED, int(cpu_capacity()))

    memory = available_memory_bytes()
    by_memory = (
        max(MIN_RECOMMENDED, int(memory // SCANNER_MEMORY_BYTES))
        if memory is not None
        else MAX_RECOMMENDED
    )

    return max(MIN_RECOMMENDED, min(by_cpu, by_memory, MAX_RECOMMENDED))


def describe_capacity() -> str:
    """One line for the logs, so a slow run can be explained afterwards."""
    memory = available_memory_bytes()
    memory_text = f"{memory / (1024**3):.1f} GiB available" if memory else "memory unknown"
    return f"{cpu_capacity():.2g} usable CPU(s), {memory_text}"


def _cgroup_cpu_quota() -> float | None:
    """Cores permitted by the cgroup, v2 first then v1, or None if unlimited."""
    text = _read(_CGROUP_V2_CPU)
    if text:
        parts = text.split()
        if len(parts) == 2 and parts[0] != "max":
            quota, period = _to_float(parts[0]), _to_float(parts[1])
            if quota and period and period > 0:
                return quota / period
        return None

    quota = _to_float(_read(_CGROUP_V1_QUOTA))
    period = _to_float(_read(_CGROUP_V1_PERIOD))
    if quota is not None and quota > 0 and period:
        return quota / period
    return None


def _cgroup_memory_limit() -> int | None:
    for path in (_CGROUP_V2_MEMORY, _CGROUP_V1_MEMORY):
        text = _read(path)
        if not text or text == "max":
            continue
        value = _to_float(text)
        # cgroup v1 writes an enormous sentinel to mean "no limit"; anything
        # at that scale is not a real container budget.
        if value is not None and 0 < value < (1 << 62):
            return int(value)
    return None


def _meminfo_available() -> int | None:
    text = _read(_MEMINFO)
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("MemAvailable:"):
            parts = line.split()
            if len(parts) >= 2:
                value = _to_float(parts[1])
                if value is not None:
                    return int(value * 1024)  # reported in kB
    return None


def _read(path: Path) -> str:
    """Read a small pseudo-file, treating every failure as "not present".

    These paths are absent on macOS, absent outside containers, and
    unreadable under some sandboxes. None of that is an error worth
    surfacing: the caller simply falls back to the next source.
    """
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _to_float(text: str | None) -> float | None:
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        logger.debug(f"Unexpected value in a resource limit file: {text!r}")
        return None
