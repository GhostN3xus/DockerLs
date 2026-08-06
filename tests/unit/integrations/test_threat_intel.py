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
