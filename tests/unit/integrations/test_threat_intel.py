from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dockerls.integrations.threat_intel.client import ThreatIntelClient


class TestThreatIntelClient:
    @pytest.mark.asyncio
    async def test_known_exploited_matches_kev_catalog(self):
        client = ThreatIntelClient()
        kev_payload = {"vulnerabilities": [{"cveID": "CVE-2024-0001"}]}
        request = httpx.Request("GET", "https://x")
        resp = httpx.Response(200, json=kev_payload, request=request)
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            result = await client.known_exploited(["CVE-2024-0001", "CVE-2024-9999"])
        assert result == {"CVE-2024-0001"}

    @pytest.mark.asyncio
    async def test_kev_unreachable_degrades_gracefully(self):
        client = ThreatIntelClient()
        with patch(
            "httpx.AsyncClient.get",
            AsyncMock(
                side_effect=httpx.ConnectError("boom", request=httpx.Request("GET", "https://x"))
            ),
        ):
            result = await client.known_exploited(["CVE-2024-0001"])
        assert result == set()

    @pytest.mark.asyncio
    async def test_epss_scores_parsed(self):
        client = ThreatIntelClient()
        payload = {"data": [{"cve": "CVE-2024-0001", "epss": "0.87"}]}
        request = httpx.Request("GET", "https://x")
        resp = httpx.Response(200, json=payload, request=request)
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=resp)):
            scores = await client.epss_scores(["CVE-2024-0001"])
        assert scores == {"CVE-2024-0001": 0.87}

    @pytest.mark.asyncio
    async def test_epss_unreachable_degrades_gracefully(self):
        client = ThreatIntelClient()
        with patch(
            "httpx.AsyncClient.get",
            AsyncMock(
                side_effect=httpx.ConnectError("boom", request=httpx.Request("GET", "https://x"))
            ),
        ):
            scores = await client.epss_scores(["CVE-2024-0001"])
        assert scores == {}

    @pytest.mark.asyncio
    async def test_empty_input_short_circuits(self):
        client = ThreatIntelClient()
        assert await client.known_exploited([]) == set()
        assert await client.epss_scores([]) == {}


class TestEpssBatching:
    """A API do FIRST pagina o resultado. Pedir todos os CVEs de uma vez
    devolvia calado só a primeira página, e o sinal de EPSS sumia justamente
    nas imagens com mais CRITICAL/HIGH -- as que mais precisam dele."""

    @pytest.mark.asyncio
    async def test_more_than_one_page_of_cves_is_fully_resolved(self):
        client = ThreatIntelClient()
        cve_ids = [f"CVE-2026-{i:05d}" for i in range(250)]

        seen_batches: list[list[str]] = []

        async def fake_get(self, url, params=None, **kwargs):
            requested = params["cve"].split(",")
            seen_batches.append(requested)
            return httpx.Response(
                200,
                json={"data": [{"cve": c, "epss": "0.5"} for c in requested]},
                request=httpx.Request("GET", url),
            )

        with patch.object(httpx.AsyncClient, "get", fake_get):
            scores = await client.epss_scores(cve_ids)

        assert len(scores) == 250, "CVEs beyond the first page lost their EPSS score"
        assert len(seen_batches) == 3
        assert all(len(b) <= ThreatIntelClient.EPSS_BATCH_SIZE for b in seen_batches)

    @pytest.mark.asyncio
    async def test_an_explicit_limit_is_sent_so_the_default_cannot_truncate(self):
        client = ThreatIntelClient()
        captured: dict[str, str] = {}

        async def fake_get(self, url, params=None, **kwargs):
            captured.update(params)
            return httpx.Response(200, json={"data": []}, request=httpx.Request("GET", url))

        with patch.object(httpx.AsyncClient, "get", fake_get):
            await client.epss_scores(["CVE-2026-0001", "CVE-2026-0002"])

        assert captured["limit"] == "2"

    @pytest.mark.asyncio
    async def test_one_failed_batch_does_not_discard_the_others(self):
        """Sinal parcial ainda é melhor que nenhum."""
        client = ThreatIntelClient()
        cve_ids = [f"CVE-2026-{i:05d}" for i in range(150)]
        calls = {"n": 0}

        async def fake_get(self, url, params=None, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise httpx.ConnectError("boom")
            requested = params["cve"].split(",")
            return httpx.Response(
                200,
                json={"data": [{"cve": c, "epss": "0.9"} for c in requested]},
                request=httpx.Request("GET", url),
            )

        with patch.object(httpx.AsyncClient, "get", fake_get):
            scores = await client.epss_scores(cve_ids)

        assert len(scores) == 50


class TestKevIsFetchedOnce:
    """`recommend` enriches every tag concurrently. The KEV memo is only
    populated after a download completes, so without a lock a 100-tag run
    started 100 simultaneous downloads of the same multi-megabyte catalogue.
    """

    @pytest.mark.asyncio
    async def test_concurrent_lookups_share_one_download(self):
        import asyncio

        client = ThreatIntelClient()
        calls = 0

        async def slow_get(self, url, **kwargs):
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.01)
            return httpx.Response(
                200,
                json={"vulnerabilities": [{"cveID": "CVE-2024-0001"}]},
                request=httpx.Request("GET", url),
            )

        with patch("httpx.AsyncClient.get", slow_get):
            results = await asyncio.gather(
                *[client.known_exploited(["CVE-2024-0001"]) for _ in range(25)]
            )

        assert calls == 1, f"KEV catalogue downloaded {calls} times for one run"
        assert all(r == {"CVE-2024-0001"} for r in results)
