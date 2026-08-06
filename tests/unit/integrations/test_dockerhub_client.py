from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from tenacity import RetryError

from dockerls.integrations.dockerhub.client import DockerHubClient


def _response(status_code: int, json_body: dict | None = None, headers: dict | None = None):
    request = httpx.Request("GET", "https://hub.docker.com/v2/x")
    return httpx.Response(status_code, json=json_body, headers=headers or {}, request=request)


class TestParseImages:
    def test_prefers_amd64(self):
        images = [
            {"architecture": "arm64", "size": 10, "digest": "sha256:arm"},
            {"architecture": "amd64", "size": 20, "digest": "sha256:amd"},
        ]
        size, digest, arch, archs = DockerHubClient._parse_images(images)
        assert arch == "amd64"
        assert digest == "sha256:amd"
        assert archs == ["arm64", "amd64"]

    def test_falls_back_to_first_when_no_amd64(self):
        images = [{"architecture": "arm64", "size": 5, "digest": "sha256:arm"}]
        size, digest, arch, archs = DockerHubClient._parse_images(images)
        assert arch == "arm64"
        assert archs == ["arm64"]

    def test_empty_images(self):
        size, digest, arch, archs = DockerHubClient._parse_images([])
        assert size == 0
        assert digest == ""
        assert archs == []


class TestSearchTagsPartialResults:
    @pytest.mark.asyncio
    async def test_network_error_mid_pagination_returns_partial_results(self):
        client = DockerHubClient()
        page1 = {
            "results": [{"name": "22-alpine", "images": [{"architecture": "amd64"}]}],
            "next": "https://hub.docker.com/v2/x?page=2",
        }

        call_count = {"n": 0}

        async def fake_get_json(_self, _client, _url):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _response(200, page1)
            raise httpx.ConnectError("boom", request=httpx.Request("GET", "https://x"))

        with patch.object(DockerHubClient, "_get_json", fake_get_json):
            tags = await client.search_tags("node", limit=100)

        assert len(tags) == 1
        assert tags[0].tag == "22-alpine"

    @pytest.mark.asyncio
    async def test_populates_multi_arch_field(self):
        client = DockerHubClient()
        page = {
            "results": [
                {
                    "name": "22-alpine",
                    "images": [
                        {"architecture": "amd64", "size": 10, "digest": "sha256:a"},
                        {"architecture": "arm64", "size": 9, "digest": "sha256:b"},
                    ],
                }
            ],
            "next": None,
        }
        mock_get_json = AsyncMock(return_value=_response(200, page))
        with patch.object(DockerHubClient, "_get_json", mock_get_json):
            tags = await client.search_tags("node", limit=100)

        assert tags[0].available_architectures == ["amd64", "arm64"]


class TestRetryAfter:
    @pytest.mark.asyncio
    async def test_get_json_sleeps_for_retry_after_header(self):
        client = DockerHubClient()
        resp_429 = _response(429, {}, headers={"Retry-After": "3"})

        with (
            patch("httpx.AsyncClient.get", AsyncMock(return_value=resp_429)),
            patch("asyncio.sleep", AsyncMock()) as mock_sleep,
        ):
            async with await client._get_client() as http_client:
                with pytest.raises(RetryError):
                    await client._get_json(http_client, "https://hub.docker.com/v2/x")

        retry_after_calls = [c for c in mock_sleep.await_args_list if c.args == (3.0,)]
        assert len(retry_after_calls) >= 1
