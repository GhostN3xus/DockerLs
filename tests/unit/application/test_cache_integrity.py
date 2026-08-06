"""A cache hit is a claim about a past scan; it must be re-validated.

1.1.0 shipped a bug where a cached entry was trusted on sight. The gate is
only worth something if it survives the shapes a real cache goes bad in:
truncated JSON, a payload from an older schema, a persisted ERROR status,
and a stale entry with no scan at all.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.interfaces.cache_store import CacheStoreInterface
from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from dockerls.domain.interfaces.scanner import ScannerInterface

TAG = DockerImage(name="node", tag="22-alpine", is_official=True)
KEY = f"analysis:{TAG.full_reference}"


class _Repo(ImageRepositoryInterface):
    async def search_tags(self, image_name, limit=100):
        return [TAG]

    async def get_image_metadata(self, image_name, tag):
        return None

    async def tag_exists(self, image_name, tag):
        return True


class _EOL(EOLCheckerInterface):
    async def is_eol(self, product, version):
        return False

    async def is_lts(self, product, version):
        return False


class _CountingScanner(ScannerInterface):
    def __init__(self):
        self.scans = 0

    async def is_available(self):
        return True

    async def scan(self, image_reference):
        self.scans += 1
        return ScanResult(
            image_reference=image_reference,
            scan_timestamp=datetime.now(tz=UTC).isoformat(),
        )


class _Cache(CacheStoreInterface):
    def __init__(self, payload):
        self.store = {KEY: payload} if payload is not None else {}
        self.deleted: list[str] = []

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ttl_seconds=86400):
        self.store[key] = value

    async def delete(self, key):
        self.deleted.append(key)
        self.store.pop(key, None)

    async def clear(self):
        self.store.clear()


def _poisoned(status, timestamp="2026-01-01T00:00:00Z"):
    return ImageAnalysis(
        image=TAG,
        scan=ScanResult(
            image_reference=TAG.full_reference,
            status=status,
            error_message="trivy exited 1" if status != ScanStatus.OK else "",
            scan_timestamp=timestamp,
        ),
        security_score=100.0,
        tier="S",
        remediation_score=100,
    ).model_dump()


async def _run(cache_payload):
    cache = _Cache(cache_payload)
    scanner = _CountingScanner()
    result = await RecommendImagesUseCase(
        repository=_Repo(),
        scanner=scanner,
        eol_checker=_EOL(),
        cache=cache,
    ).execute("node")
    return result, cache, scanner


class TestCorruptedPayloadsAreDiscarded:
    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param({"garbage": True}, id="unknown_shape"),
            pytest.param({"image": {"name": "node"}}, id="truncated"),
            pytest.param({}, id="empty_dict"),
            pytest.param("not-a-dict", id="wrong_type"),
            pytest.param([1, 2, 3], id="list_instead_of_object"),
            pytest.param(None, id="missing"),
        ],
    )
    @pytest.mark.asyncio
    async def test_unusable_payload_forces_a_real_scan(self, payload):
        result, _, scanner = await _run(payload)

        assert scanner.scans == 1, "the corrupted entry was trusted"
        assert result.recommendations
        assert result.recommendations[0].scan.is_verified

    @pytest.mark.asyncio
    async def test_schema_mismatch_is_deleted_not_reused(self):
        _, cache, _ = await _run({"garbage": True})
        assert KEY in cache.deleted


class TestPersistedFailureStatusIsNeverTrusted:
    @pytest.mark.parametrize("status", [ScanStatus.ERROR, ScanStatus.TIMEOUT, ScanStatus.PARTIAL])
    @pytest.mark.asyncio
    async def test_cached_failed_scan_is_rescanned(self, status):
        result, cache, scanner = await _run(_poisoned(status))

        assert scanner.scans == 1, f"a cached {status.value} scan was reused"
        assert KEY in cache.deleted
        assert result.recommendations[0].scan.status is ScanStatus.OK

    @pytest.mark.asyncio
    async def test_cached_scan_without_a_timestamp_is_rescanned(self):
        """A default-constructed ScanResult has status OK and no timestamp
        -- the shape a "no data" fallback would persist."""
        result, cache, scanner = await _run(_poisoned(ScanStatus.OK, timestamp=""))

        assert scanner.scans == 1
        assert KEY in cache.deleted
        assert result.recommendations[0].scan.scan_timestamp != ""

    @pytest.mark.asyncio
    async def test_a_perfect_score_does_not_buy_trust(self):
        """The poisoned entries all carry score=100 / tier=S; the gate must
        key on scan status alone."""
        _, _, scanner = await _run(_poisoned(ScanStatus.ERROR))
        assert scanner.scans == 1


class TestValidCacheEntriesAreStillUsed:
    """The gate must not degrade the cache into a no-op."""

    @pytest.mark.asyncio
    async def test_verified_entry_skips_the_scanner(self):
        good = ImageAnalysis(
            image=TAG,
            scan=ScanResult(
                image_reference=TAG.full_reference,
                scan_timestamp="2026-01-01T00:00:00Z",
            ),
            security_score=98.0,
            tier="S",
            remediation_score=100,
        ).model_dump()

        result, cache, scanner = await _run(good)

        assert scanner.scans == 0, "a valid cache entry was ignored"
        assert cache.deleted == []
        assert result.recommendations[0].security_score == 98.0


class TestCacheKeyIsSchemaVersioned:
    def test_entries_from_an_older_schema_cannot_be_read(self, tmp_path):
        """Bumping CACHE_SCHEMA_VERSION must orphan old rows rather than
        letting them deserialize into the new shape."""
        from dockerls.cache import sqlite_cache
        from dockerls.cache.sqlite_cache import SQLiteCache

        cache = SQLiteCache(tmp_path / "cache.db")
        import asyncio

        asyncio.run(cache.set("analysis:node:22", {"security_score": 100}))

        original = sqlite_cache.CACHE_SCHEMA_VERSION
        try:
            sqlite_cache.CACHE_SCHEMA_VERSION = "v-next"
            assert asyncio.run(cache.get("analysis:node:22")) is None
        finally:
            sqlite_cache.CACHE_SCHEMA_VERSION = original

        assert asyncio.run(cache.get("analysis:node:22")) is not None
