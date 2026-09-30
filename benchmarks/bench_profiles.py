"""SIMULATED comparison of the execution profiles (quick / standard / audit).

    python benchmarks/bench_profiles.py --repeat 5

Same world (a repository with many tags, fake scanner and fake threat-intel
feed with fixed latencies) run under each profile's settings. What it shows is
how much *work* each profile asks for -- scans, intel requests, checks left
pending -- and how that turns into time when a scan takes `--scan-latency`.

Not simulated, and therefore not in the numbers: the second-scanner
cross-validation of the finalists, which needs a second scanner. Its cost in a
real run is what `bench_real.py` observes, if it is run with Grype installed.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger

from benchmarks._common import Row, Sample, emit, environment, summarize
from benchmarks.bench_pipeline import _SlowIntel, build_world
from dockerls.domain.value_objects.execution_profile import PROFILES


async def run_profile(name: str, args: argparse.Namespace) -> Row:
    profile = next(p for key, p in PROFILES.items() if key.value == name)
    samples: list[Sample] = []
    pending = 0
    for _ in range(args.repeat):
        world = build_world(
            args.tags, scan_latency=args.scan_latency, resolve_latency=args.resolve_latency
        )
        intel = _SlowIntel(args.intel_latency)
        use_case = world.use_case(
            scan_budget=profile.scan_budget,
            threat_intel=intel,
            enrichment=profile.enrichment,
            inspect_finalists=profile.inspect_finalists,
            profile_name=profile.name.value,
            not_performed_by_profile=profile.not_performed(),
            spread=True,
            max_concurrency=4,
        )
        started = time.perf_counter()
        result = await use_case.execute("node", limit=500)
        seconds = time.perf_counter() - started
        pending = len(result.pending_checks)
        samples.append(
            Sample(
                seconds,
                {
                    "scans": float(len(world.scanner.calls)),
                    "intel_requests": float(intel.requests["kev"] + intel.requests["epss"]),
                    "pending_checks": float(pending),
                    "measured": float(result.total_tags_analyzed),
                },
            )
        )
    return summarize(
        f"profile {name} (scan budget {profile.scan_budget or 'all'}, "
        f"enrichment {profile.enrichment.value})",
        "simulated",
        samples,
    )


async def main_async(args: argparse.Namespace) -> None:
    logger.remove()
    logger.add(sys.stderr, level="ERROR")
    rows = [await run_profile(name, args) for name in ("quick", "standard", "audit")]
    emit(
        "DockerLs execution profiles (SIMULATED registry, scanner and feeds)",
        environment(),
        {
            "repeat": args.repeat,
            "tags_in_repository": args.tags,
            "scan_latency_s": args.scan_latency,
            "resolve_latency_s": args.resolve_latency,
            "intel_latency_s": args.intel_latency,
            "not_simulated": "second-scanner cross-validation",
        },
        rows,
        args.json,
    )


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repeat", type=int, default=5)
    p.add_argument("--tags", type=int, default=60)
    p.add_argument("--scan-latency", type=float, default=0.20)
    p.add_argument("--resolve-latency", type=float, default=0.03)
    p.add_argument("--intel-latency", type=float, default=0.05)
    p.add_argument("--json", default=None)
    asyncio.run(main_async(p.parse_args()))


if __name__ == "__main__":
    main()
