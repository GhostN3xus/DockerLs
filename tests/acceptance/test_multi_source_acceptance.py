"""End-to-end acceptance for the multi-source engine.

The pipeline below is the real one -- real use case, real composite
repository, real scoring, real ranking -- with only the registry HTTP and
the scanner binaries stubbed. What is being asserted is behaviour a unit
test cannot reach:

* tags that share a manifest digest cost **one** scan, no matter which
  source they came from;
* a source whose registry refuses to serve is reported as unverified and is
  never ranked;
* the digest a candidate is recommended under is the one it was scanned at.
"""

from __future__ import annotations

from typing import Any

import pytest

from dockerls.application.services.composite_repository import CompositeImageRepository
from dockerls.application.services.hardening_analysis import HardeningAnalyzer
from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.image_facts import EvidenceSource, HardeningFacts
from dockerls.domain.entities.scan_result import ScanErrorKind, ScanResult, ScanStatus
from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.domain.value_objects.confidence import Confidence
from dockerls.domain.value_objects.tristate import Tristate

SHARED_DIGEST = "sha256:" + "a" * 64
UNIQUE_DIGEST = "sha256:" + "b" * 64


class _Source:
    """An image source with a fixed answer and a recorded host."""

    def __init__(self, label: str, images: list[DockerImage], host: str = ""):
        self.source = label
        self.host = host
        self._images = images

    async def search_tags(self, image_name: str, limit: int = 100) -> list[DockerImage]:
        return [image.model_copy(deep=True) for image in self._images[:limit]]

    async def get_image_metadata(self, image_name: str, tag: str) -> DockerImage | None:
        return None

    async def tag_exists(self, image_name: str, tag: str) -> bool | None:
        return True


class _CountingScanner:
    """Counts invocations, so deduplication is measured rather than assumed."""

    def __init__(self, failing: set[str] | None = None):
        self.scanned: list[str] = []
        self._failing = failing or set()

    async def scan(self, image_reference: str) -> ScanResult:
        self.scanned.append(image_reference)
        if any(image_reference.startswith(prefix) for prefix in self._failing):
            return ScanResult(
                image_reference=image_reference,
                scanner="trivy",
                status=ScanStatus.ERROR,
                error_kind=ScanErrorKind.AUTH_REQUIRED,
                error_message="unauthorized: authentication required",
                scan_timestamp="2026-01-01T00:00:00Z",
            )
        return ScanResult(
            image_reference=image_reference,
            scanner="trivy",
            status=ScanStatus.OK,
            scan_timestamp="2026-01-01T00:00:00Z",
            vulnerabilities=[],
            os_family="debian",
        )

    async def is_available(self) -> bool:
        return True


class _EOL(EOLCheckerInterface):
    async def is_eol(self, product: str, version: str) -> bool:
        return False

    async def is_lts(self, product: str, version: str) -> bool:
        return False


class _Inspector:
    """A registry that pins tags to digests and reports one config."""

    def __init__(self, digests: dict[str, str], facts: HardeningFacts | None = None):
        self._digests = digests
        self._facts = facts or HardeningFacts()
        self.inspections: list[str] = []

    async def resolve_digest(self, image: DockerImage) -> str:
        return self._digests.get(image.full_reference, "")

    async def inspect(self, image: DockerImage) -> tuple[str, HardeningFacts]:
        self.inspections.append(image.full_reference)
        return self._digests.get(image.full_reference, ""), self._facts

    async def close(self) -> None:
        return None


def _use_case(sources: list[Any], scanner: _CountingScanner, inspector: _Inspector | None):
    composite = CompositeImageRepository(sources[0], sources[1:], extra_limit=10)
    return RecommendImagesUseCase(
        repository=composite,
        scanner=scanner,
        eol_checker=_EOL(),
        workers=4,
        max_medium=50,
        hardening=HardeningAnalyzer(inspector=inspector),  # type: ignore[arg-type]
    )


class TestCrossSourceDeduplication:
    async def test_tags_sharing_a_digest_are_scanned_once_across_sources(self):
        """Four references, two distinct images, two scans.

        The aliases here are deliberately split across two catalogues: the
        deduplication has to happen on the resolved digest, not on anything
        source-local, or a hardened catalogue's mirror of a Docker Hub
        manifest is paid for twice.
        """
        hub = _Source(
            "Docker Hub",
            [DockerImage(name="node", tag="22"), DockerImage(name="node", tag="22-bookworm")],
        )
        mirror = _Source(
            "Chainguard",
            [
                DockerImage(name="cgr.dev/chainguard/node", tag="latest", source="Chainguard"),
                DockerImage(name="cgr.dev/chainguard/node", tag="latest-dev", source="Chainguard"),
            ],
            host="cgr.dev",
        )
        scanner = _CountingScanner()
        inspector = _Inspector(
            {
                "node:22": SHARED_DIGEST,
                "node:22-bookworm": SHARED_DIGEST,
                "cgr.dev/chainguard/node:latest": SHARED_DIGEST,
                "cgr.dev/chainguard/node:latest-dev": UNIQUE_DIGEST,
            }
        )

        result = await _use_case([hub, mirror], scanner, inspector).execute("node")

        assert result.metrics.tags_discovered == 4
        assert result.metrics.digests_resolved == 4
        assert result.metrics.unique_digests == 2
        assert result.metrics.duplicates_collapsed == 2
        assert len(scanner.scanned) == 2

    async def test_without_digest_resolution_nothing_collapses(self):
        """The control case: the saving comes from the digests, not luck."""
        hub = _Source(
            "Docker Hub",
            [DockerImage(name="node", tag="22"), DockerImage(name="node", tag="22-bookworm")],
        )
        scanner = _CountingScanner()
        result = await _use_case([hub], scanner, None).execute("node")

        assert result.metrics.digests_resolved == 0
        assert result.metrics.unique_digests == 2
        assert len(scanner.scanned) == 2


class TestUnscannableSourcesAreNeverRanked:
    async def test_a_registry_that_refuses_yields_unverified_not_a_recommendation(self):
        """Exactly the Docker Hardened Images case without credentials.

        The catalogue is public and full of hardening claims; the registry
        will not serve the image. The claims must not become a verdict.
        """
        hub = _Source("Docker Hub", [DockerImage(name="node", tag="22")])
        dhi = _Source(
            "Docker Hardened Images",
            [DockerImage(name="dhi.io/node", tag="22-debian13", source="Docker Hardened Images")],
            host="dhi.io",
        )
        scanner = _CountingScanner(failing={"dhi.io/"})

        result = await _use_case([hub, dhi], scanner, None).execute("node")

        ranked = [a.image.full_reference for a in result.recommendations or result.alternatives]
        assert "dhi.io/node:22-debian13" not in ranked
        unverified = {u.image_reference: u for u in result.unverified}
        assert "dhi.io/node:22-debian13" in unverified
        assert unverified["dhi.io/node:22-debian13"].kind == "AUTH_REQUIRED"

    async def test_a_ranked_candidate_always_carries_a_confidence(self):
        hub = _Source("Docker Hub", [DockerImage(name="node", tag="22")])
        result = await _use_case([hub], _CountingScanner(), None).execute("node")
        for analysis in result.recommendations or result.alternatives:
            assert analysis.confidence is not Confidence.UNVERIFIED
            assert analysis.confidence_reasons
            assert analysis.why


class TestDigestFirstRecommendations:
    async def test_a_recommendation_names_the_digest_it_was_scanned_at(self):
        hub = _Source("Docker Hub", [DockerImage(name="node", tag="22")])
        inspector = _Inspector({"node:22": SHARED_DIGEST})
        result = await _use_case([hub], _CountingScanner(), inspector).execute("node")

        best = (result.recommendations or result.alternatives)[0]
        assert best.image.digest == SHARED_DIGEST
        assert best.pinned_reference == f"node@{SHARED_DIGEST}"
        assert "pinned to a resolved manifest digest" in best.why

    async def test_hardening_evidence_reaches_the_finalists_only(self):
        """Ten candidates, five finalists: inspection is not paid per tag."""
        hub = _Source(
            "Docker Hub",
            [DockerImage(name="node", tag=f"2{i}") for i in range(10)],
        )
        inspector = _Inspector(
            {f"node:2{i}": f"sha256:{i}{'c' * 63}" for i in range(10)},
            facts=HardeningFacts(
                runs_as_non_root=Tristate.TRUE,
                user="node",
                has_shell=Tristate.FALSE,
                has_package_manager=Tristate.FALSE,
                config_verified=True,
                evidence={"runs_as_non_root": EvidenceSource.REGISTRY},
            ),
        )
        result = await _use_case([hub], _CountingScanner(), inspector).execute("node")

        assert len(inspector.inspections) <= 5
        best = (result.recommendations or result.alternatives)[0]
        assert best.hardening.reportable
        assert best.hardening.score > 0
        assert best.facts.is_verified("runs_as_non_root")


@pytest.mark.parametrize("include_hardening", [True, False])
async def test_the_json_payload_always_carries_the_new_dimensions(include_hardening):
    """`--format json` must not depend on whether inspection succeeded."""
    hub = _Source("Docker Hub", [DockerImage(name="node", tag="22")])
    inspector = _Inspector({"node:22": SHARED_DIGEST}) if include_hardening else None
    result = await _use_case([hub], _CountingScanner(), inspector).execute("node")

    payload = result.model_dump()
    best = (payload["recommendations"] or payload["alternatives"])[0]
    for key in ("hardening", "attack_surface", "confidence", "why", "trade_offs", "facts"):
        assert key in best
    assert set(best["hardening"]) >= {"score", "coverage", "reportable"}
    assert payload["metrics"]["digests_resolved"] == (1 if include_hardening else 0)
