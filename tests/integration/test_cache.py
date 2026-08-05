import pytest
import tempfile
from pathlib import Path

from dockerls.cache.sqlite_cache import SQLiteCache


@pytest.fixture
def cache(tmp_path):
    return SQLiteCache(tmp_path / "test_cache.db")


class TestSQLiteCache:
    @pytest.mark.asyncio
    async def test_set_and_get(self, cache):
        await cache.set("key1", {"data": "value"})
        result = await cache.get("key1")
        assert result == {"data": "value"}

    @pytest.mark.asyncio
    async def test_get_missing(self, cache):
        result = await cache.get("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete(self, cache):
        await cache.set("key1", "val")
        await cache.delete("key1")
        assert await cache.get("key1") is None

    @pytest.mark.asyncio
    async def test_clear(self, cache):
        await cache.set("a", 1)
        await cache.set("b", 2)
        await cache.clear()
        assert await cache.get("a") is None
        assert await cache.get("b") is None

    @pytest.mark.asyncio
    async def test_expired(self, cache):
        await cache.set("exp", "data", ttl_seconds=0)
        result = await cache.get("exp")
        assert result is None

    @pytest.mark.asyncio
    async def test_overwrite(self, cache):
        await cache.set("key", "v1")
        await cache.set("key", "v2")
        assert await cache.get("key") == "v2"
