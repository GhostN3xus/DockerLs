from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dockerls.integrations.nvd.client import NVDClient


def _response(status_code: int, json_body: dict | None = None):
    request = httpx.Request("GET", "https://services.nvd.nist.gov/x")
    return httpx.Response(status_code, json=json_body, request=request)


class TestNVDClient:
    def test_rate_limit_without_key(self):
        client = NVDClient()
        assert client._min_interval == pytest.approx(30 / 5)

    def test_rate_limit_with_key(self):
        client = NVDClient(api_key="my-key")
        assert client._min_interval == pytest.approx(30 / 50)

    @pytest.mark.asyncio
    async def test_get_cve_details_success(self):
        client = NVDClient()
        payload = {"vulnerabilities": [{"cve": {"id": "CVE-2024-0001", "references": []}}]}
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=_response(200, payload))):
            details = await client.get_cve_details("CVE-2024-0001")
        assert details == {"id": "CVE-2024-0001", "references": []}

    @pytest.mark.asyncio
    async def test_get_cve_details_not_found(self):
        client = NVDClient()
        payload = {"vulnerabilities": []}
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=_response(200, payload))):
            details = await client.get_cve_details("CVE-9999-9999")
        assert details is None

    @pytest.mark.asyncio
    async def test_get_cve_details_rate_limited(self):
        client = NVDClient()
        with patch("httpx.AsyncClient.get", AsyncMock(return_value=_response(403))):
            details = await client.get_cve_details("CVE-2024-0001")
        assert details is None

    @pytest.mark.asyncio
    async def test_get_cve_details_http_error_degrades_gracefully(self):
        client = NVDClient()
        with patch(
            "httpx.AsyncClient.get",
            AsyncMock(
                side_effect=httpx.ConnectError("boom", request=httpx.Request("GET", "https://x"))
            ),
        ):
            details = await client.get_cve_details("CVE-2024-0001")
        assert details is None

    @pytest.mark.asyncio
    async def test_has_known_exploit_true(self):
        client = NVDClient()
        details = {"references": [{"tags": ["Exploit"]}]}
        with patch.object(client, "get_cve_details", AsyncMock(return_value=details)):
            assert await client.has_known_exploit("CVE-2024-0001") is True

    @pytest.mark.asyncio
    async def test_has_known_exploit_false_when_no_details(self):
        client = NVDClient()
        with patch.object(client, "get_cve_details", AsyncMock(return_value=None)):
            assert await client.has_known_exploit("CVE-2024-0001") is False

    @pytest.mark.asyncio
    async def test_has_known_exploit_false_without_exploit_tag(self):
        client = NVDClient()
        details = {"references": [{"tags": ["Vendor Advisory"]}]}
        with patch.object(client, "get_cve_details", AsyncMock(return_value=details)):
            assert await client.has_known_exploit("CVE-2024-0001") is False

    @pytest.mark.asyncio
    async def test_throttle_sleeps_when_called_rapidly(self):
        client = NVDClient()
        with patch("asyncio.sleep", AsyncMock()) as mock_sleep:
            await client._throttle()
            await client._throttle()
        assert mock_sleep.await_count >= 1
