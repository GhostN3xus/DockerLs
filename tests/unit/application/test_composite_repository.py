from __future__ import annotations

import pytest

from dockerls.application.services.composite_repository import CompositeImageRepository
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface


class _Source(ImageRepositoryInterface):
    def __init__(self, name, tags, source="Docker Hub", host="", fails=False, existing=None):
        self._name = name
        self._tags = tags
        self._source = source
        self.host = host
        self._fails = fails
        self._existing = existing
        self.searched_with_limit: int | None = None
        self.tag_checks: list[tuple[str, str]] = []

    async def search_tags(self, image_name, limit=100):
        if self._fails:
            raise RuntimeError(f"{self._name} is down")
        self.searched_with_limit = limit
        return [
            DockerImage(name=self._name, tag=t, source=self._source) for t in self._tags[:limit]
        ]

    async def get_image_metadata(self, image_name, tag):
        if self._fails:
            raise RuntimeError(f"{self._name} is down")
        if tag in self._tags:
            return DockerImage(name=self._name, tag=tag, source=self._source)
        return None

    async def tag_exists(self, image_name, tag):
        self.tag_checks.append((image_name, tag))
        if self._existing is None:
            return None
        return tag in self._existing


def _hub(tags=("22-alpine", "20-slim")):
    return _Source("node", list(tags), existing=set(tags))


def _chainguard(tags=("latest",)):
    return _Source(
        "cgr.dev/chainguard/node",
        list(tags),
        source="Chainguard",
        host="cgr.dev",
        existing=set(tags),
    )


class TestFanOut:
    @pytest.mark.asyncio
    async def test_all_sources_contribute_to_one_candidate_list(self):
        composite = CompositeImageRepository(_hub(), [_chainguard()])
        images = await composite.search_tags("node")

        assert {i.source for i in images} == {"Docker Hub", "Chainguard"}
        assert "cgr.dev/chainguard/node:latest" in {i.full_reference for i in images}

    @pytest.mark.asyncio
    async def test_hardened_sources_get_their_own_smaller_limit(self):
        """These catalogues hold a handful of tags; requesting 100 from them
        just wastes a round trip."""
        hub, cgr = _hub(), _chainguard()
        composite = CompositeImageRepository(hub, [cgr], extra_limit=3)
        await composite.search_tags("node", limit=100)

        assert hub.searched_with_limit == 100
        assert cgr.searched_with_limit == 3

    @pytest.mark.asyncio
    async def test_duplicate_references_are_collapsed(self):
        a = _Source("node", ["22-alpine"])
        b = _Source("node", ["22-alpine"])
        composite = CompositeImageRepository(a, [b])

        images = await composite.search_tags("node")
        assert len(images) == 1

    @pytest.mark.asyncio
    async def test_primary_results_come_first(self):
        composite = CompositeImageRepository(_hub(), [_chainguard()])
        images = await composite.search_tags("node")

        assert images[0].source == "Docker Hub"


class TestOneBadSourceDoesNotBreakTheSearch:
    @pytest.mark.asyncio
    async def test_failing_hardened_source_is_skipped(self):
        broken = _Source("cgr.dev/chainguard/node", [], host="cgr.dev", fails=True)
        composite = CompositeImageRepository(_hub(), [broken])

        images = await composite.search_tags("node")
        assert [i.source for i in images] == ["Docker Hub", "Docker Hub"]

    @pytest.mark.asyncio
    async def test_failing_primary_still_returns_hardened_results(self):
        broken = _Source("node", [], fails=True)
        composite = CompositeImageRepository(broken, [_chainguard()])

        images = await composite.search_tags("node")
        assert [i.source for i in images] == ["Chainguard"]

    @pytest.mark.asyncio
    async def test_all_sources_failing_yields_empty(self):
        composite = CompositeImageRepository(
            _Source("node", [], fails=True),
            [_Source("cgr.dev/chainguard/node", [], host="cgr.dev", fails=True)],
        )
        assert await composite.search_tags("node") == []


class TestTagVerificationRouting:
    @pytest.mark.asyncio
    async def test_hardened_reference_is_checked_against_its_own_registry(self):
        hub, cgr = _hub(), _chainguard()
        composite = CompositeImageRepository(hub, [cgr])

        assert await composite.tag_exists("cgr.dev/chainguard/node", "latest") is True
        # The bare query name is what the source's own mapping expects.
        assert cgr.tag_checks == [("node", "latest")]
        assert hub.tag_checks == []

    @pytest.mark.asyncio
    async def test_hub_reference_is_checked_against_the_hub(self):
        hub, cgr = _hub(), _chainguard()
        composite = CompositeImageRepository(hub, [cgr])

        assert await composite.tag_exists("node", "22-alpine") is True
        assert hub.tag_checks == [("node", "22-alpine")]
        assert cgr.tag_checks == []

    @pytest.mark.asyncio
    async def test_missing_hardened_tag_reports_false(self):
        composite = CompositeImageRepository(_hub(), [_chainguard(tags=("latest",))])
        assert await composite.tag_exists("cgr.dev/chainguard/node", "bogus") is False

    @pytest.mark.asyncio
    async def test_check_failure_is_unknown_not_missing(self):
        class _Raises(_Source):
            async def tag_exists(self, image_name, tag):
                raise RuntimeError("network down")

        broken = _Raises("node", ["22-alpine"])
        composite = CompositeImageRepository(broken, [])
        assert await composite.tag_exists("node", "22-alpine") is None


class TestMetadataLookup:
    @pytest.mark.asyncio
    async def test_falls_through_to_the_source_that_has_it(self):
        composite = CompositeImageRepository(_hub(tags=()), [_chainguard()])
        found = await composite.get_image_metadata("node", "latest")

        assert found is not None
        assert found.source == "Chainguard"

    @pytest.mark.asyncio
    async def test_returns_none_when_no_source_has_it(self):
        composite = CompositeImageRepository(_hub(), [_chainguard()])
        assert await composite.get_image_metadata("node", "nonexistent") is None
