"""Stored credentials must actually reach the wire.

1.1.0 shipped a bug where `authenticate()` existed and was never called.
Fixing the call site is not the same as proving the token is sent: these
tests assert on the actual `Authorization` header of the outgoing request,
not on internal state.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dockerls.integrations.dockerhub.client import DockerHubClient

TOKEN = "dckr_pat_AbCdEf123456789xyz"
JWT = "eyJhbGciOiJIUzI1NiJ9.payload.signature"


# Captured before any patching: referring to httpx.AsyncClient from inside
# the replacement would resolve to the patch itself.
_REAL_ASYNC_CLIENT = httpx.AsyncClient


def _use_transport(transport):
    """Patch httpx.AsyncClient so every client built uses `transport`."""

    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _REAL_ASYNC_CLIENT(transport=transport, **kwargs)

    return patch.object(httpx, "AsyncClient", factory)


class _CapturingTransport(httpx.AsyncBaseTransport):
    """Records every request instead of sending it."""

    def __init__(self, json_body=None, status_code=200):
        self.requests: list[httpx.Request] = []
        self._json = json_body or {"results": [], "next": None}
        self._status = status_code

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self._status, json=self._json, request=request)

    @property
    def auth_headers(self) -> list[str | None]:
        return [r.headers.get("Authorization") for r in self.requests]


class TestAuthenticateSendsCredentials:
    @pytest.mark.asyncio
    async def test_login_posts_the_username_and_token(self):
        transport = _CapturingTransport(json_body={"token": JWT})
        client = DockerHubClient(username="alice", token=TOKEN)

        with _use_transport(transport):
            assert await client.authenticate() is True

        assert len(transport.requests) == 1
        request = transport.requests[0]
        assert request.url.path.endswith("/users/login/")
        assert request.method == "POST"
        body = request.content.decode()
        assert "alice" in body
        assert TOKEN in body

    @pytest.mark.asyncio
    async def test_no_credentials_means_no_request_at_all(self):
        transport = _CapturingTransport()
        client = DockerHubClient()

        with _use_transport(transport):
            assert await client.authenticate() is False

        assert transport.requests == []


class TestTokenIsAttachedToSubsequentRequests:
    """Authenticating is pointless if the resulting token is then dropped."""

    @pytest.mark.asyncio
    async def test_search_tags_carries_the_bearer_token(self):
        transport = _CapturingTransport()
        client = DockerHubClient(username="alice", token=TOKEN)
        client._auth_token = JWT  # as set by a successful authenticate()

        with _use_transport(transport):
            await client.search_tags("node", limit=1)

        assert transport.requests, "no request was made"
        assert transport.auth_headers[0] == f"Bearer {JWT}"

    @pytest.mark.asyncio
    async def test_tag_exists_carries_the_bearer_token(self):
        transport = _CapturingTransport(json_body={"name": "22-alpine"})
        client = DockerHubClient(username="alice", token=TOKEN)
        client._auth_token = JWT

        with _use_transport(transport):
            await client.tag_exists("node", "22-alpine")

        assert transport.auth_headers[0] == f"Bearer {JWT}"

    @pytest.mark.asyncio
    async def test_anonymous_client_sends_no_authorization_header(self):
        transport = _CapturingTransport()
        client = DockerHubClient()

        with _use_transport(transport):
            await client.search_tags("node", limit=1)

        assert transport.auth_headers[0] is None


class TestDependencyWiringAuthenticates:
    """The call site regression itself: `build_repository` must authenticate
    when credentials exist, and must not when they do not."""

    @pytest.mark.asyncio
    async def test_stored_credentials_trigger_authentication(self):
        from dockerls.cli import dependencies

        dependencies._settings.cache_clear()
        with (
            patch.object(dependencies, "load_credentials", return_value=("alice", TOKEN)),
            patch.object(DockerHubClient, "authenticate", AsyncMock(return_value=True)) as auth,
        ):
            client = await dependencies.build_repository()

        auth.assert_awaited_once()
        assert client._username == "alice"
        assert client._token == TOKEN
        dependencies._settings.cache_clear()

    @pytest.mark.asyncio
    async def test_no_credentials_skips_authentication(self):
        from dockerls.cli import dependencies

        dependencies._settings.cache_clear()
        with (
            patch.object(dependencies, "load_credentials", return_value=("", "")),
            patch.object(DockerHubClient, "authenticate", AsyncMock()) as auth,
        ):
            await dependencies.build_repository()

        auth.assert_not_awaited()
        dependencies._settings.cache_clear()


class TestCredentialsNeverLandInLogs:
    @pytest.mark.asyncio
    async def test_failed_auth_does_not_log_the_token(self, tmp_path):
        from loguru import logger

        from dockerls.infrastructure.logging.setup import setup_logging

        path = setup_logging("DEBUG", log_dir=tmp_path / "logs")
        client = DockerHubClient(username="alice", token=TOKEN)

        def _boom(request):
            raise httpx.ConnectError("boom")

        with _use_transport(httpx.MockTransport(_boom)):
            await client.authenticate()

        logger.complete()
        logger.remove()
        assert TOKEN not in path.read_text()
