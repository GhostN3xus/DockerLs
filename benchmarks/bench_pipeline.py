"""SIMULATED pipeline benchmarks: the real orchestration, fake registry/scanner.

    python benchmarks/bench_pipeline.py --repeat 5 --json benchmarks/results/pipeline.json

Every latency below is an *input* (see `--scan-latency` and friends) and is
printed with the results. What is measured is the application's own behaviour
under those latencies: how many scans a scenario costs, how much the caches
and the single-flight save, how well independent work overlaps. Nothing here
says how fast any real registry, threat-intel feed or scanner is -- that is
`bench_real.py`.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger

from benchmarks._common import Row, Sample, emit, environment, summarize
from dockerls.application.services.measurement import MeasurementService
from dockerls.application.services.measurement_store import MeasurementStore
from dockerls.application.use_cases.analyze_image import AnalyzeImageUseCase
from dockerls.application.use_cases.compare_images import CompareImagesUseCase
from dockerls.domain.entities.image import DockerImage
from tests.unit.application.recommend_harness import Eol, FakeIntel, Repo, World


class _SlowResolver:
    """Adds a per-call latency to identity resolution (one HEAD-like round trip)."""

    def __init__(self, inner: Any, latency: float) -> None:
        self._inner = inner
        self._latency = latency

    async def resolve_identity(
        self, name: str, tag: str, digest: str = "", platform: Any = None
    ) -> Any:
        await asyncio.sleep(self._latency)
        return await self._inner.resolve_identity(name, tag, digest, platform)

    def __getattr__(self, item: str) -> Any:
        return getattr(self._inner, item)


class _SlowIntel(FakeIntel):
    def __init__(self, delay: float, *, available: bool = True) -> None:
        super().__init__({"CVE-2026-0100"}, available=available)
        self._delay = delay

    async def known_exploited(self, cve_ids: list[str]) -> set[str]:
        await asyncio.sleep(self._delay)
        return await super().known_exploited(cve_ids)

    async def epss_scores(self, cve_ids: list[str]) -> dict[str, float]:
        await asyncio.sleep(self._delay)
        return await super().epss_scores(cve_ids)


def _digest(seed: str) -> str:
    """A distinct, well-formed digest per seed (the test helper repeats short
    seeds, so `1` and `11` would collide at scale)."""
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def build_world(
    tags: int, *, scan_latency: float, resolve_latency: float, distinct: int | None = None
) -> World:
    """`tags` tags over `distinct` different images (default: all different)."""
    world = World()
    world.scanner.latency = scan_latency
    distinct = distinct or tags
    manifests = [_digest(f"manifest-{i}") for i in range(distinct)]
    for n in range(tags):
        tag = f"{n + 1}-alpine"
        manifest = manifests[n % distinct]
        world.resolver.publish(
            "node",
            tag,
            _digest(f"index-{n}"),
            linux_amd64=manifest,
            linux_arm64=_digest(f"arm-{n}"),
        )
        world.scanner.findings[manifest] = (n % distinct) % 4
        world.scanner.cve_offsets[manifest] = (n % distinct) * 100
        world.scanner.live_tags[f"node:{tag}"] = manifest
        world.tags.append(DockerImage(name="node", tag=tag, is_official=True))
    world.resolver = _SlowResolver(world.resolver, resolve_latency)  # type: ignore[assignment]
    return world


def _counters(use_case: Any, world: World) -> dict[str, float]:
    stats = use_case._measurement.stats
    return {
        "scans": float(len(world.scanner.calls)),
        "cache_hits": float(stats.cache_hits),
        "dedup": float(stats.duplicates_avoided),
    }


async def _recommend(world: World, *, intel: Any = None, budget: int = 0, **kw: Any) -> Sample:
    use_case = world.use_case(scan_budget=budget, threat_intel=intel, max_concurrency=4, **kw)
    started = time.perf_counter()
    await use_case.execute("node", limit=200)
    return Sample(time.perf_counter() - started, _counters(use_case, world))


async def cold_warm(args: argparse.Namespace) -> list[Row]:
    rows: list[Row] = []
    for label, tags in (("small", args.small), ("large", args.large)):
        cold: list[Sample] = []
        warm: list[Sample] = []
        for _ in range(args.repeat):
            world = build_world(
                tags, scan_latency=args.scan_latency, resolve_latency=args.resolve_latency
            )
            cold.append(await _recommend(world))
            world.scanner.calls.clear()
            warm.append(await _recommend(world))
        rows.append(summarize(f"recommend {label} ({tags} tags), cold cache", "simulated", cold))
        rows.append(
            summarize(
                f"recommend {label} ({tags} tags), warm cache",
                "simulated",
                warm,
                "second run over the same store: scans should be 0",
            )
        )
    return rows


async def same_digest(args: argparse.Namespace) -> list[Row]:
    samples: list[Sample] = []
    for _ in range(args.repeat):
        world = build_world(
            args.large,
            scan_latency=args.scan_latency,
            resolve_latency=args.resolve_latency,
            distinct=args.large // 6,
        )
        samples.append(await _recommend(world))
    return [
        summarize(
            f"recommend {args.large} tags -> {args.large // 6} distinct digests",
            "simulated",
            samples,
            "scans should equal the number of distinct digests, not of tags",
        )
    ]


async def compare(args: argparse.Namespace) -> list[Row]:
    rows: list[Row] = []
    for count in (2, 8):
        samples: list[Sample] = []
        for _ in range(args.repeat):
            world = build_world(
                count, scan_latency=args.scan_latency, resolve_latency=args.resolve_latency
            )
            service = MeasurementService(
                world.scanner,
                resolver=world.resolver,
                store=MeasurementStore(world.cache),
                max_concurrency=4,
            )
            analyze = AnalyzeImageUseCase(
                Repo(world.tags), world.scanner, Eol(), measurement=service
            )
            started = time.perf_counter()
            await CompareImagesUseCase(analyze).execute(
                [f"node:{i + 1}-alpine" for i in range(count)]
            )
            samples.append(
                Sample(
                    time.perf_counter() - started,
                    {
                        "scans": float(len(world.scanner.calls)),
                        "concurrency": float(world.scanner.max_in_flight),
                    },
                )
            )
        rows.append(summarize(f"compare {count} images (limit 4)", "simulated", samples))
    return rows


async def intel_sources(args: argparse.Namespace) -> list[Row]:
    rows: list[Row] = []
    cases = (
        ("intel healthy", lambda: _SlowIntel(args.intel_latency), ""),
        ("intel slow", lambda: _SlowIntel(args.slow_intel_latency), ""),
        (
            "intel unavailable",
            lambda: _SlowIntel(args.intel_latency, available=False),
            "the fake reports 'no answer'; telling absent / error / rate limited / invalid "
            "apart is covered by tests/unit/integrations/test_threat_intel_sharing.py, "
            "not timed here",
        ),
    )
    for label, factory, note in cases:
        samples = []
        for _ in range(args.repeat):
            world = build_world(
                args.small, scan_latency=args.scan_latency, resolve_latency=args.resolve_latency
            )
            intel = factory()
            sample = await _recommend(world, intel=intel)
            sample.counters["kev_requests"] = float(intel.requests["kev"])
            samples.append(sample)
        rows.append(summarize(f"recommend {args.small} tags, {label}", "simulated", samples, note))
    return rows


async def simultaneous(args: argparse.Namespace) -> list[Row]:
    samples: list[Sample] = []
    for _ in range(args.repeat):
        world = build_world(
            args.small, scan_latency=args.scan_latency, resolve_latency=args.resolve_latency
        )
        started = time.perf_counter()
        # Three runs of the same question over one shared store, started together.
        await asyncio.gather(*(_recommend(world) for _ in range(3)))
        samples.append(
            Sample(time.perf_counter() - started, {"scans": float(len(world.scanner.calls))})
        )
    return [
        summarize(
            f"3 simultaneous recommend runs ({args.small} tags, shared store)",
            "simulated",
            samples,
            "separate runs have separate single-flights: without a warm store each may scan; "
            "the persisted store is what stops the *next* run from repeating them",
        )
    ]


async def main_async(args: argparse.Namespace) -> None:
    logger.remove()
    logger.add(sys.stderr, level="ERROR")
    rows: list[Row] = []
    for scenario in (cold_warm, same_digest, compare, intel_sources, simultaneous):
        rows += await scenario(args)
    emit(
        "DockerLs pipeline benchmark (SIMULATED registry and scanner)",
        environment(),
        {
            "repeat": args.repeat,
            "scan_latency_s": args.scan_latency,
            "resolve_latency_s": args.resolve_latency,
            "intel_latency_s": args.intel_latency,
            "slow_intel_latency_s": args.slow_intel_latency,
        },
        rows,
        args.json,
    )


def main() -> None:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--repeat", type=int, default=5)
    p.add_argument("--small", type=int, default=6)
    p.add_argument("--large", type=int, default=36)
    p.add_argument("--scan-latency", type=float, default=0.20)
    p.add_argument("--resolve-latency", type=float, default=0.03)
    p.add_argument("--intel-latency", type=float, default=0.05)
    p.add_argument("--slow-intel-latency", type=float, default=1.0)
    p.add_argument("--json", default=None)
    asyncio.run(main_async(p.parse_args()))


if __name__ == "__main__":
    main()
