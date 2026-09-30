"""One question, asked once: shared lookups, confirmed absences, honest failures.

The properties that matter for a security signal are these: the same CVE is
not fetched once per candidate; a confirmed "OSV has no record" is remembered
(shortly), while a network error, a 429 or a garbled body is *never* stored
as an absence; and a source that could not answer leaves the finding UNKNOWN
rather than "not exploitable".
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from dockerls.domain.interfaces.cache_store import CacheStoreInterface
from dockerls.integrations.threat_intel.client import ThreatIntelClient
from dockerls.integrations.threat_intel.osv import OSVClient
from dockerls.integrations.threat_intel.status import IntelStatus


class _Cache(CacheStoreInterface):
    def __init__(self) -> None:
        self.rows: dict[str, Any] = {}
        self.ttls: dict[str, int] = {}

    async def get(self, key: str) -> Any | None:
        return self.rows.get(key)

    async def set(self, key: str, value: Any, ttl_seconds: int = 86400) -> None:
        self.rows[key] = value
        self.ttls[key] = ttl_seconds

    async def delete(self, key: str) -> None:
        self.rows.pop(key, None)

    async def clear(self) -> None:
        self.rows.clear()


def _osv(handler, cache=None) -> OSVClient:
    client = OSVClient(cache=cache, max_attempts=1, backoff_base=0.0)
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))  # noqa: SLF001
    return client


def _epss(handler, cache=None) -> ThreatIntelClient:
    client = ThreatIntelClient(cache=cache, max_attempts=1, backoff_base=0.0)
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))  # noqa: SLF001
    return client


OSV_RECORD = {"aliases": ["GHSA-aaaa-bbbb-cccc"], "affected": []}


class TestOSVSharing:
    async def test_concurrent_candidates_asking_for_the_same_cve_send_one_request(self):
        seen: list[str] = []

        async def slow(request: httpx.Request) -> httpx.Response:
            seen.append(request.url.path)
            await asyncio.sleep(0.05)
            return httpx.Response(200, json=OSV_RECORD)

        client = _osv(slow)

        results = await asyncio.gather(
            *(client.enrich(["CVE-2026-0001", "CVE-2026-0002"]) for _ in range(6))
        )

        assert sorted(seen) == ["/v1/vulns/CVE-2026-0001", "/v1/vulns/CVE-2026-0002"]
        assert all(set(r) == {"CVE-2026-0001", "CVE-2026-0002"} for r in results)
        assert client.requests == 2
        assert client.joined == 10

    async def test_the_same_client_and_connections_are_reused(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=OSV_RECORD)

        client = OSVClient(max_attempts=1)
        first = await client._client()  # noqa: SLF001
        assert await client._client() is first  # noqa: SLF001
        await client.close()
        assert client._http is None  # noqa: SLF001

    async def test_simultaneous_requests_are_bounded(self):
        active = peak = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.02)
            active -= 1
            return httpx.Response(200, json=OSV_RECORD)

        client = _osv(handler)
        await client.enrich([f"CVE-2026-{i:04d}" for i in range(40)])

        assert 1 < peak <= OSVClient.MAX_CONCURRENT


class TestOSVAbsenceVersusFailure:
    async def test_a_404_is_a_confirmed_absence_and_is_remembered_with_its_own_ttl(self):
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            return httpx.Response(404)

        cache = _Cache()
        first = _osv(handler, cache)
        assert await first.enrich(["CVE-2026-0404"]) == {}
        assert first.status_of("CVE-2026-0404") is IntelStatus.ABSENT
        assert first.available is True, "a 404 is a real answer from a live source"

        second = _osv(handler, cache)
        assert await second.enrich(["CVE-2026-0404"]) == {}
        assert second.status_of("CVE-2026-0404") is IntelStatus.ABSENT
        assert calls == 1, "the absence was served from the cache"
        (ttl,) = [v for k, v in cache.ttls.items() if "absent" in k]
        assert ttl == OSVClient.ABSENT_TTL_SECONDS < OSVClient.CACHE_TTL_SECONDS

    @pytest.mark.parametrize(
        ("response", "expected"),
        [
            pytest.param(httpx.Response(500), IntelStatus.NETWORK_ERROR, id="server-error"),
            pytest.param(httpx.Response(429), IntelStatus.RATE_LIMITED, id="rate-limited"),
            pytest.param(
                httpx.Response(200, content=b"<html>"), IntelStatus.INVALID_RESPONSE, id="garbled"
            ),
            pytest.param(
                httpx.Response(200, json=["not", "an", "object"]),
                IntelStatus.INVALID_RESPONSE,
                id="wrong-shape",
            ),
            pytest.param(httpx.Response(403), IntelStatus.INVALID_RESPONSE, id="forbidden"),
        ],
    )
    async def test_a_failure_is_never_stored_as_an_absence(self, response, expected):
        cache = _Cache()
        client = _osv(lambda request: response, cache)

        result = await client.enrich(["CVE-2026-0001"])

        assert result == {}
        assert client.status_of("CVE-2026-0001") is expected
        assert not expected.answered
        assert cache.rows == {}, "nothing was learned, so nothing may be remembered"
        assert client.available is False

    async def test_a_dropped_connection_is_a_network_error_not_an_absence(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route to host")

        cache = _Cache()
        client = _osv(handler, cache)

        assert await client.enrich(["CVE-2026-0001"]) == {}
        assert client.status_of("CVE-2026-0001") is IntelStatus.NETWORK_ERROR
        assert cache.rows == {}

    async def test_a_failed_lookup_is_retried_next_time_not_remembered(self):
        outcomes = [httpx.Response(500), httpx.Response(200, json=OSV_RECORD)]

        def handler(request: httpx.Request) -> httpx.Response:
            return outcomes.pop(0)

        client = _osv(handler, _Cache())
        assert await client.enrich(["CVE-2026-0001"]) == {}
        recovered = await client.enrich(["CVE-2026-0001"])

        assert set(recovered) == {"CVE-2026-0001"}
        assert client.status_of("CVE-2026-0001") is IntelStatus.FOUND

    async def test_a_positive_answer_is_cached_under_the_long_ttl(self):
        cache = _Cache()
        client = _osv(lambda request: httpx.Response(200, json=OSV_RECORD), cache)

        await client.enrich(["CVE-2026-0001"])

        (ttl,) = [v for k, v in cache.ttls.items() if "absent" not in k]
        assert ttl == OSVClient.CACHE_TTL_SECONDS


class TestEPSSSharing:
    @staticmethod
    def _handler(seen: list[list[str]]):
        async def handler(request: httpx.Request) -> httpx.Response:
            cves = request.url.params["cve"].split(",")
            seen.append(cves)
            await asyncio.sleep(0.03)
            return httpx.Response(
                200,
                json={"data": [{"cve": c, "epss": "0.5", "percentile": "0.9"} for c in cves]},
            )

        return handler

    async def test_overlapping_candidates_fetch_each_cve_once(self):
        seen: list[list[str]] = []
        client = _epss(self._handler(seen))

        results = await asyncio.gather(
            client.epss_scores(["CVE-2026-0001", "CVE-2026-0002"]),
            client.epss_scores(["CVE-2026-0002", "CVE-2026-0003"]),
            client.epss_scores(["CVE-2026-0001", "CVE-2026-0003"]),
        )

        fetched = [cve for batch in seen for cve in batch]
        assert sorted(fetched) == ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"]
        assert all(len(r) == 2 for r in results)
        assert all(score == 0.5 for r in results for score in r.values())
        assert client.joined >= 1

    async def test_a_lookup_is_batched_not_one_request_per_cve(self):
        seen: list[list[str]] = []
        client = _epss(self._handler(seen))

        await client.epss_scores([f"CVE-2026-{i:04d}" for i in range(50)])

        assert len(seen) == 1 and len(seen[0]) == 50

    async def test_a_cve_learned_this_run_is_not_asked_again_even_without_a_cache(self):
        seen: list[list[str]] = []
        client = _epss(self._handler(seen))

        await client.epss_scores(["CVE-2026-0001"])
        again = await client.epss_scores(["CVE-2026-0001"])

        assert len(seen) == 1
        assert again == {"CVE-2026-0001": 0.5}

    async def test_a_failed_batch_is_not_an_absence_and_releases_its_waiters(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(0.02)
            return httpx.Response(503)

        cache = _Cache()
        client = _epss(handler, cache)

        first, second = await asyncio.gather(
            client.epss_scores(["CVE-2026-0001"]), client.epss_scores(["CVE-2026-0001"])
        )

        assert first == second == {}
        assert client.epss_status_of("CVE-2026-0001") is IntelStatus.NETWORK_ERROR
        assert client.epss_available is False
        assert cache.rows == {}

    async def test_rate_limiting_is_named_as_such(self):
        client = _epss(lambda request: httpx.Response(429))

        await client.epss_scores(["CVE-2026-0001"])

        assert client.epss_status_of("CVE-2026-0001") is IntelStatus.RATE_LIMITED

    async def test_a_cve_the_feed_does_not_know_is_absent_only_when_the_feed_was_sane(self):
        def handler(request: httpx.Request) -> httpx.Response:
            cves = request.url.params["cve"].split(",")
            known = [c for c in cves if c != "CVE-2026-9999"]
            return httpx.Response(
                200, json={"data": [{"cve": c, "epss": "0.1", "percentile": "0.2"} for c in known]}
            )

        cache = _Cache()
        client = _epss(handler, cache)
        await client.epss_scores(["CVE-2026-0001", "CVE-2026-9999"])

        assert client.epss_status_of("CVE-2026-0001") is IntelStatus.FOUND
        assert client.epss_status_of("CVE-2026-9999") is IntelStatus.ABSENT
        assert any("epss-absent" in key for key in cache.rows)

    async def test_an_empty_answer_proves_nothing_and_is_not_cached_as_absence(self):
        client_cache = _Cache()
        client = _epss(lambda request: httpx.Response(200, json={"data": []}), client_cache)

        await client.epss_scores(["CVE-2026-0001"])

        assert client.epss_status_of("CVE-2026-0001") is IntelStatus.INVALID_RESPONSE
        assert client.epss_available is False
        assert client_cache.rows == {}

    async def test_the_shared_client_is_reused_across_lookups_and_closable(self):
        client = ThreatIntelClient(max_attempts=1)
        first = await client._client()  # noqa: SLF001
        assert await client._client() is first  # noqa: SLF001
        await client.close()
        assert client._http is None  # noqa: SLF001
