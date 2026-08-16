"""A tag listing is fetched once per run, not once per candidate.

`recommend` asks each source for the same listing repeatedly: once to
discover candidates, then once more for every candidate `_verify_tags`
confirms. Each of those calls used to open its own connection pool, eat a
401, fetch a token and re-download an identical payload. Measured against a
mock transport, verifying the ten candidates of a single Chainguard
repository cost 33 requests where 3 do the job.

These tests pin the request *count*, because that is the property that
regressed and the one a rate-limited registry actually cares about.
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import httpx
import pytest

from dockerls.integrations.dockerhub.client import DockerHubClient
from dockerls.integrations.registry.hardened import ChainguardRepository
from dockerls.integrations.registry.oci import OCIRegistryClient

_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _counting_transport(handler):
    """Wrap `handler`, recording every request that reaches it."""
    seen: list[httpx.Request] = []

    async def counting(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return await handler(request)

    transport = httpx.MockTransport(counting)

    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _REAL_ASYNC_CLIENT(transport=transport, **kwargs)

    return patch.object(httpx, "AsyncClient", factory), seen


async def _tags_handler(request: httpx.Request) -> httpx.Response:
    """A registry that behaves like the real ones: 401 + token, then data."""
    url = str(request.url)
    if "token" in url:
        return httpx.Response(200, json={"token": "anon"})
    if request.headers.get("Authorization") is None:
        return httpx.Response(
            401,
            headers={"WWW-Authenticate": 'Bearer realm="https://cgr.dev/token",service="cgr.dev"'},
        )
    return httpx.Response(200, json={"name": "chainguard/node", "tags": ["latest", "22", "20"]})


class TestOCIListingIsFetchedOnce:
    async def test_repeated_calls_hit_the_network_once(self):
        patcher, seen = _counting_transport(_tags_handler)
        with patcher:
            client = OCIRegistryClient("cgr.dev")
            first = await client.list_tags("chainguard/node")
            for _ in range(9):
                assert await client.list_tags("chainguard/node") == first
            await client.close()

        # One 401, one token, one successful listing.
        assert len(seen) == 3

    async def test_concurrent_first_calls_collapse_into_one_request(self):
        """Verification runs the candidates in parallel, so a plain cache
        with no single-flight guard would still let all ten through."""
        patcher, seen = _counting_transport(_tags_handler)
        with patcher:
            client = OCIRegistryClient("cgr.dev")
            results = await asyncio.gather(
                *[client.list_tags("chainguard/node") for _ in range(10)]
            )
            await client.close()

        assert all(r == results[0] for r in results)
        assert len(seen) == 3

    async def test_a_missing_repository_is_asked_about_once(self):
        """The `None` outcome is memoised too: a 404 per candidate is the
        same waste as a 200 per candidate."""

        async def missing(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        patcher, seen = _counting_transport(missing)
        with patcher:
            client = OCIRegistryClient("cgr.dev")
            for _ in range(5):
                assert await client.list_tags("chainguard/nope") is None
            await client.close()

        assert len(seen) == 1

    async def test_different_repositories_are_still_fetched_separately(self):
        patcher, seen = _counting_transport(_tags_handler)
        with patcher:
            client = OCIRegistryClient("cgr.dev")
            await client.list_tags("chainguard/node")
            await client.list_tags("chainguard/python")
            await client.close()

        assert len({str(r.url) for r in seen if "tags/list" in str(r.url)}) == 2


class TestHardenedVerificationIsFree:
    async def test_verifying_every_candidate_costs_no_extra_requests(self):
        patcher, seen = _counting_transport(_tags_handler)
        with patcher:
            repo = ChainguardRepository()
            tags = await repo.search_tags("node", limit=10)
            before = len(seen)
            checks = await asyncio.gather(*[repo.tag_exists("node", t.tag) for t in tags])
            after = len(seen)
            await repo.close()

        assert tags, "the fixture must produce candidates for this to mean anything"
        assert all(c is True for c in checks)
        assert after == before, "tag verification re-fetched a listing it already had"


class TestDockerHubConnectionReuse:
    async def test_one_client_serves_the_whole_run(self):
        client = DockerHubClient()
        first = await client._get_client()
        second = await client._get_client()
        assert first is second
        await client.close()
        assert client._client is None

    async def test_auth_token_applies_to_an_already_created_client(self):
        """The header is attached per request, so authenticating after the
        client exists still authenticates the traffic."""
        client = DockerHubClient()
        assert client._auth_headers() == {}
        client._auth_token = "tok"  # noqa: S105 - test double
        assert client._auth_headers() == {"Authorization": "Bearer tok"}
        await client.close()

    async def test_concurrent_checks_for_the_same_tag_make_one_request(self):
        seen: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            await asyncio.sleep(0.01)
            return httpx.Response(200, json={"name": "22-alpine"})

        patcher, _ = _counting_transport(handler)
        with patcher:
            client = DockerHubClient()
            results = await asyncio.gather(
                *[client.tag_exists("node", "22-alpine") for _ in range(8)]
            )
            await client.close()

        assert results == [True] * 8
        assert len(seen) == 1, "a cold cache let every concurrent check reach the network"

    async def test_a_failed_check_does_not_poison_later_ones(self):
        """The in-flight entry must be cleared on the error path too, or a
        transient outage would pin the failure for the rest of the run."""
        state = {"down": True}

        async def handler(request: httpx.Request) -> httpx.Response:
            if state["down"]:
                raise httpx.ConnectError("down")
            return httpx.Response(200, json={"name": "22-alpine"})

        patcher, _ = _counting_transport(handler)
        with patcher:
            # `max_attempts=1` keeps the retry policy from turning the
            # outage into a success on its own.
            client = DockerHubClient(max_attempts=1)
            assert await client.tag_exists("node", "22-alpine") is None
            assert not client._tag_checks, "a failed check left an in-flight entry behind"
            state["down"] = False
            assert await client.tag_exists("node", "22-alpine") is True
            await client.close()


class TestRepositoriesAreClosed:
    async def test_execute_releases_the_connection_pools(self):
        from unittest.mock import AsyncMock

        from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase

        source = AsyncMock()
        source.search_tags = AsyncMock(return_value=[])
        source.close = AsyncMock()

        use_case = RecommendImagesUseCase(
            repository=source, scanner=AsyncMock(), eol_checker=AsyncMock()
        )
        await use_case.execute("node")

        source.close.assert_awaited_once()

    async def test_a_source_without_a_pool_is_left_alone(self):
        from unittest.mock import AsyncMock

        from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase

        class NoClose:
            async def search_tags(self, image_name, limit=100):
                return []

        use_case = RecommendImagesUseCase(
            repository=NoClose(), scanner=AsyncMock(), eol_checker=AsyncMock()
        )
        result = await use_case.execute("node")
        assert result.total_tags_scanned == 0

    async def test_a_failing_close_does_not_lose_the_result(self):
        from unittest.mock import AsyncMock

        from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase

        source = AsyncMock()
        source.search_tags = AsyncMock(return_value=[])
        source.close = AsyncMock(side_effect=RuntimeError("pool already gone"))

        use_case = RecommendImagesUseCase(
            repository=source, scanner=AsyncMock(), eol_checker=AsyncMock()
        )
        result = await use_case.execute("node")
        assert result.query == "node"


@pytest.mark.parametrize("source_cls", [ChainguardRepository])
def test_hardened_sources_expose_close(source_cls):
    assert callable(getattr(source_cls, "close", None))
