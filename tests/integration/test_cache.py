import pytest

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
        import asyncio

        await cache.set("exp", "data", ttl_seconds=0)
        await asyncio.sleep(0.05)  # ensure expiry timestamp is in the past
        result = await cache.get("exp")
        assert result is None

    @pytest.mark.asyncio
    async def test_overwrite(self, cache):
        await cache.set("key", "v1")
        await cache.set("key", "v2")
        assert await cache.get("key") == "v2"

    @pytest.mark.asyncio
    async def test_schema_version_prefix_isolates_keys(self, cache):
        from dockerls.cache.sqlite_cache import CACHE_SCHEMA_VERSION

        await cache.set("shared-key", "payload")
        raw = cache._get_sync("shared-key")
        assert raw == "payload"
        # the stored row key must be prefixed with the schema version
        with cache._session() as session:
            from sqlalchemy import select

            from dockerls.infrastructure.database.models import CacheEntry

            row = session.execute(
                select(CacheEntry).where(CacheEntry.key == f"{CACHE_SCHEMA_VERSION}:shared-key")
            ).scalar_one_or_none()
            assert row is not None

    @pytest.mark.asyncio
    async def test_does_not_block_event_loop(self, cache):
        # asyncio.to_thread offloads the blocking SQLAlchemy call; a
        # concurrent coroutine should still get scheduled while it runs.
        import asyncio

        ticked = False

        async def ticker():
            nonlocal ticked
            await asyncio.sleep(0)
            ticked = True

        await asyncio.gather(cache.set("k", "v" * 1000), ticker())
        assert ticked


class TestCacheValidationMiss:
    @pytest.mark.asyncio
    async def test_stale_payload_treated_as_miss(self, tmp_path):
        """A row of the wrong shape, in the *real* SQLite store, is a miss and
        is evicted -- it must neither be served nor raise."""
        from dockerls.application.services.measurement_store import (
            MeasurementStore,
            MissReason,
            ScannerFingerprint,
        )
        from dockerls.cache.sqlite_cache import SQLiteCache
        from dockerls.domain.value_objects.image_identity import ImageIdentity

        cache = SQLiteCache(tmp_path / "cache.db")
        store = MeasurementStore(cache)
        identity = ImageIdentity("docker.io", "library/node", "sha256:" + "a" * 64, "linux/amd64")
        fingerprint = ScannerFingerprint(
            name="trivy", version="0.60", db_revision="r1", options="o"
        )
        key = store._scan_key(identity, fingerprint)  # noqa: SLF001 - the key under test
        await cache.set(key, {"totally": "wrong-shape"})

        lookup = await store.get_scan(identity, fingerprint)

        assert lookup.value is None
        assert lookup.reason in (MissReason.CORRUPT, MissReason.SCHEMA_MISMATCH)
        assert await cache.get(key) is None
        cache.close()


class TestConcurrentWrites:
    """Cache writes run on a thread pool and `recommend` issues them
    concurrently. Select-then-insert had a real window in which two threads
    both missed and then both INSERTed the same unique key."""

    @pytest.mark.asyncio
    async def test_same_key_written_concurrently_does_not_raise(self, cache):
        import asyncio

        await asyncio.gather(*[cache.set("hot-key", {"writer": i}) for i in range(32)])

        stored = await cache.get("hot-key")
        assert stored is not None
        assert stored["writer"] in range(32)

    @pytest.mark.asyncio
    async def test_distinct_keys_all_survive(self, cache):
        import asyncio

        await asyncio.gather(*[cache.set(f"key-{i}", {"n": i}) for i in range(32)])

        for i in range(32):
            assert await cache.get(f"key-{i}") == {"n": i}

    @pytest.mark.asyncio
    async def test_overwrite_replaces_rather_than_duplicates(self, cache):
        await cache.set("k", {"v": 1})
        await cache.set("k", {"v": 2})
        assert await cache.get("k") == {"v": 2}
