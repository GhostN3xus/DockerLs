from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dockerls.integrations.endoflife.checker import (
    DOCKER_TO_ENDOFLIFE,
    EndOfLifeChecker,
    _cycle_matches,
    _version_parts,
)


class TestVersionParsing:
    def test_version_parts(self):
        assert _version_parts("3.12.4") == (3, 12, 4)
        assert _version_parts("22") == (22,)
        assert _version_parts("") == ()

    def test_cycle_matches_exact(self):
        assert _cycle_matches("22", "22") is True

    def test_cycle_matches_prefix(self):
        assert _cycle_matches("3.12.4", "3.12") is True

    def test_cycle_does_not_falsely_match_similar_prefix(self):
        # "3.12" must not match cycle "3.1" via naive string prefix matching
        assert _cycle_matches("3.12", "3.1") is False

    def test_cycle_no_match(self):
        assert _cycle_matches("3.9", "3.12") is False


class TestProductMapping:
    def test_node_maps_to_nodejs(self):
        assert DOCKER_TO_ENDOFLIFE["node"] == "nodejs"

    def test_postgres_maps_to_postgresql(self):
        assert DOCKER_TO_ENDOFLIFE["postgres"] == "postgresql"

    def test_unmapped_product_falls_back_to_itself(self):
        checker = EndOfLifeChecker()
        assert checker._resolve_product("some-unknown-image") == "some-unknown-image"


class TestEndOfLifeChecker:
    @pytest.mark.asyncio
    async def test_is_eol_uses_mapped_slug(self):
        checker = EndOfLifeChecker()
        fetch = AsyncMock(return_value=[{"cycle": "18", "eol": "2025-04-30"}])
        with patch.object(checker, "_fetch_product", fetch):
            await checker.is_eol("node", "18.19.0")
        fetch.assert_awaited_once_with("node")

    @pytest.mark.asyncio
    async def test_is_eol_true_for_past_date(self):
        checker = EndOfLifeChecker()
        with patch.object(
            checker,
            "_fetch_product",
            AsyncMock(return_value=[{"cycle": "18", "eol": "2020-01-01"}]),
        ):
            assert await checker.is_eol("node", "18.19.0") is True

    @pytest.mark.asyncio
    async def test_is_eol_false_for_future_date(self):
        checker = EndOfLifeChecker()
        with patch.object(
            checker,
            "_fetch_product",
            AsyncMock(return_value=[{"cycle": "22", "eol": "2099-01-01"}]),
        ):
            assert await checker.is_eol("node", "22.4.0") is False

    @pytest.mark.asyncio
    async def test_is_lts(self):
        checker = EndOfLifeChecker()
        with patch.object(
            checker,
            "_fetch_product",
            AsyncMock(return_value=[{"cycle": "22", "lts": True}]),
        ):
            assert await checker.is_lts("node", "22.4.0") is True

    @pytest.mark.asyncio
    async def test_no_version_returns_false(self):
        checker = EndOfLifeChecker()
        assert await checker.is_eol("node", "") is False
        assert await checker.is_lts("node", "") is False

    @pytest.mark.asyncio
    async def test_python_minor_version_matches_correct_cycle(self):
        checker = EndOfLifeChecker()
        cycles = [
            {"cycle": "3.9", "eol": "2025-10-05"},
            {"cycle": "3.12", "eol": "2028-10-31"},
        ]
        with patch.object(checker, "_fetch_product", AsyncMock(return_value=cycles)):
            assert await checker.is_eol("python", "3.12.4") is False


class TestUnknownProductIsCachedOnce:
    """Um 404 é resposta definitiva: o produto não está no catálogo.

    Sem cachear, cada uma das ~100 tags de uma execução repetia a mesma
    consulta perdida (duas, contando is_eol e is_lts). Além do desperdício,
    o volume provocava rate limiting, e aí parte das tags recebia dados e
    parte recebia lista vazia -- a mesma execução emitindo vereditos de EOL
    inconsistentes entre tags do mesmo produto.
    """

    @pytest.mark.asyncio
    async def test_a_404_is_fetched_once_for_the_whole_run(self):
        checker = EndOfLifeChecker()
        calls = {"n": 0}

        async def fake_get(self, url, **kwargs):
            calls["n"] += 1
            return httpx.Response(404, request=httpx.Request("GET", url))

        with patch.object(httpx.AsyncClient, "get", fake_get):
            for _ in range(5):
                assert await checker.is_eol("obscure-product", "1.0") is False
                assert await checker.is_lts("obscure-product", "1.0") is False

        assert calls["n"] == 1

    @pytest.mark.asyncio
    async def test_a_transient_failure_is_not_cached(self):
        """Um 5xx pode ser passageiro; cacheá-lo envenenaria a execução
        inteira com "não é EOL"."""
        checker = EndOfLifeChecker(max_attempts=1)
        calls = {"n": 0}

        async def fake_get(self, url, **kwargs):
            calls["n"] += 1
            return httpx.Response(503, request=httpx.Request("GET", url))

        with patch.object(httpx.AsyncClient, "get", fake_get):
            await checker.is_eol("node", "22")
            await checker.is_eol("node", "22")

        assert calls["n"] == 2
