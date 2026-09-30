"""A full `RecommendImagesUseCase`, wired to fakes, for behavioural tests.

Everything real except the network and the scanner binaries: the use case, the
measurement service, the layered store (over an in-memory cache), the scoring
and ranking. What a test changes is the world -- which tags exist, what each
scans to, whether a feed answers, how long a scan takes -- not the code under
test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from dockerls.application.services.events import EventStream, ListSink
from dockerls.application.services.measurement import MeasurementService
from dockerls.application.services.measurement_store import MeasurementStore
from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from tests.unit.application.measurement_fakes import (
    FakeRegistryResolver,
    FakeScanner,
    InMemoryCache,
    digest_of,
)

if TYPE_CHECKING:
    from dockerls.utils.deadline import Deadline


class Repo(ImageRepositoryInterface):
    def __init__(self, tags: list[DockerImage], *, slow: float = 0.0) -> None:
        self._tags = tags
        self._slow = slow

    async def search_tags(self, image_name: str, limit: int = 100) -> list[DockerImage]:
        if self._slow:
            import asyncio

            await asyncio.sleep(self._slow)
        return [t.model_copy(deep=True) for t in self._tags][:limit]

    async def get_image_metadata(self, image_name: str, tag: str) -> DockerImage | None:
        return None

    async def tag_exists(self, image_name: str, tag: str) -> bool:
        return True


class Eol(EOLCheckerInterface):
    async def is_eol(self, product: str, version: str) -> bool:
        return False

    async def is_lts(self, product: str, version: str) -> bool:
        return False


class FakeIntel:
    """The three things `_enrich_with_threat_intel` asks a threat-intel client."""

    def __init__(self, exploited: set[str] | None = None, *, available: bool = True) -> None:
        self.exploited = {c.upper() for c in (exploited or set())}
        self.kev_available = available
        self.epss_available = available
        self.requests = {"kev": 0, "epss": 0}
        self.joined = 0
        self.closed = False

    async def known_exploited(self, cve_ids: list[str]) -> set[str]:
        self.requests["kev"] += 1
        return {c.upper() for c in cve_ids} & self.exploited if self.kev_available else set()

    async def epss_scores(self, cve_ids: list[str]) -> dict[str, float]:
        self.requests["epss"] += 1
        return {c.upper(): 0.01 for c in cve_ids} if self.epss_available else {}

    def percentile_of(self, cve_id: str) -> float:
        return 0.1

    async def close(self) -> None:
        self.closed = True


class World:
    """Tags, their digests and what each scans to."""

    def __init__(self) -> None:
        self.resolver = FakeRegistryResolver()
        self.scanner = FakeScanner()
        self.cache = InMemoryCache()
        self.tags: list[DockerImage] = []
        self._n = 0

    def add(self, tag: str, criticals: int, *, name: str = "node", **image: Any) -> str:
        """Publish `name:tag` with `criticals` CRITICAL findings; returns its manifest digest."""
        self._n += 1
        manifest = digest_of(f"{self._n:x}")
        self.resolver.publish(
            name,
            tag,
            digest_of(f"1{self._n:x}"),
            linux_amd64=manifest,
            linux_arm64=digest_of(f"f{self._n:x}"),
        )
        self.scanner.findings[manifest] = criticals
        self.scanner.cve_offsets[manifest] = self._n * 100
        self.scanner.live_tags[f"{name}:{tag}"] = manifest
        self.tags.append(DockerImage(name=name, tag=tag, is_official=True, **image))
        return manifest

    def use_case(
        self,
        *,
        deadline: Deadline | None = None,
        events: EventStream | None = None,
        threat_intel: Any = None,
        max_concurrency: int = 2,
        min_scan_seconds: float = 0.05,
        repo: Repo | None = None,
        **kwargs: Any,
    ) -> RecommendImagesUseCase:
        service = MeasurementService(
            self.scanner,
            resolver=self.resolver,
            store=MeasurementStore(self.cache),
            deadline=deadline,
            max_concurrency=max_concurrency,
            min_scan_seconds=min_scan_seconds,
        )
        return RecommendImagesUseCase(
            repository=repo or Repo(self.tags),
            scanner=self.scanner,
            eol_checker=Eol(),
            measurement=service,
            deadline=deadline,
            events=events,
            threat_intel=threat_intel,
            max_critical=50,
            max_high=50,
            max_medium=50,
            workers=max_concurrency,
            verify_hub_tags=False,
            **kwargs,
        )


def stream() -> tuple[EventStream, ListSink]:
    sink = ListSink()
    return EventStream([sink], command="recommend", run_id="20260930T000000Z-deadbeef"), sink
