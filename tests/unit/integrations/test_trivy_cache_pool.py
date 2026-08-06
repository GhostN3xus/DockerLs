from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from dockerls.integrations.trivy.cache_pool import TrivyCachePool
from dockerls.integrations.trivy.scanner import TrivyScanner


def _seed_db(base):
    db = base / "db"
    db.mkdir(parents=True, exist_ok=True)
    (db / "trivy.db").write_bytes(b"fake-db")
    (db / "metadata.json").write_text("{}")
    return base


class TestTrivyCachePool:
    @pytest.mark.asyncio
    async def test_single_worker_uses_shared_cache_dir(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        pool = TrivyCachePool(base, size=1)
        assert await pool.prepare() is False
        async with pool.acquire() as slot:
            assert slot == base

    @pytest.mark.asyncio
    async def test_isolated_slots_are_distinct(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        pool = TrivyCachePool(base, size=3)
        assert await pool.prepare() is True

        held = []
        slots = [await pool._slots.get() for _ in range(3)]
        held.extend(slots)
        assert len({str(s) for s in held}) == 3
        assert all(s != base for s in held)
        for s in held:
            pool._slots.put_nowait(s)
        await pool.cleanup()

    @pytest.mark.asyncio
    async def test_db_is_hardlinked_not_copied(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        pool = TrivyCachePool(base, size=2)
        await pool.prepare()

        source = base / "db" / "trivy.db"
        for slot in pool._temp_dirs:
            linked = slot / "db" / "trivy.db"
            assert linked.exists()
            # Same inode => the multi-hundred-MB DB was not duplicated.
            assert linked.stat().st_ino == source.stat().st_ino
        await pool.cleanup()

    @pytest.mark.asyncio
    async def test_missing_db_degrades_to_shared_dir(self, tmp_path):
        base = tmp_path / "trivy"
        base.mkdir()
        pool = TrivyCachePool(base, size=4)
        assert await pool.prepare() is False
        async with pool.acquire() as slot:
            assert slot == base

    @pytest.mark.asyncio
    async def test_degraded_pool_serializes_concurrent_scans(self, tmp_path):
        """With one shared slot, only one scan can hold the cache dir at a
        time -- which is exactly what prevents the Trivy lock timeout."""
        base = tmp_path / "trivy"
        base.mkdir()
        pool = TrivyCachePool(base, size=4)
        await pool.prepare()

        in_flight = 0
        peak = 0

        async def worker():
            nonlocal in_flight, peak
            async with pool.acquire():
                in_flight += 1
                peak = max(peak, in_flight)
                await asyncio.sleep(0)
                in_flight -= 1

        await asyncio.gather(*[worker() for _ in range(6)])
        assert peak == 1

    @pytest.mark.asyncio
    async def test_concurrency_is_capped_at_pool_size(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        pool = TrivyCachePool(base, size=3)
        await pool.prepare()

        in_flight = 0
        peak = 0

        async def worker():
            nonlocal in_flight, peak
            async with pool.acquire():
                in_flight += 1
                peak = max(peak, in_flight)
                await asyncio.sleep(0.01)
                in_flight -= 1

        await asyncio.gather(*[worker() for _ in range(9)])
        assert peak <= 3
        await pool.cleanup()

    @pytest.mark.asyncio
    async def test_cleanup_removes_temp_dirs(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        pool = TrivyCachePool(base, size=2)
        await pool.prepare()
        dirs = list(pool._temp_dirs)
        assert dirs and all(d.exists() for d in dirs)

        await pool.cleanup()
        assert all(not d.exists() for d in dirs)
        # The shared cache dir and its DB must survive cleanup.
        assert (base / "db" / "trivy.db").exists()

    @pytest.mark.asyncio
    async def test_concurrent_first_acquire_builds_one_pool(self, tmp_path):
        """prepare() awaits before assigning its slots, so unsynchronized
        first scans could each build a full pool -- leaking temp dirs and
        handing out more slots than workers."""
        base = _seed_db(tmp_path / "trivy")
        pool = TrivyCachePool(base, size=3)

        async def use():
            async with pool.acquire():
                await asyncio.sleep(0)

        await asyncio.gather(*[use() for _ in range(5)])

        assert len(pool._temp_dirs) == 3
        assert pool._slots.qsize() == 3
        await pool.cleanup()

    @pytest.mark.asyncio
    async def test_cleanup_is_idempotent(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        pool = TrivyCachePool(base, size=2)
        await pool.prepare()
        await pool.cleanup()
        await pool.cleanup()


class _FakeProc:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self):
        return self._stdout, self._stderr


class TestTrivyScannerCacheIsolation:
    @pytest.mark.asyncio
    async def test_scan_passes_cache_dir(self, tmp_path):
        scanner = TrivyScanner(cache_dir=tmp_path / "trivy", workers=1)
        proc = _FakeProc(stdout=b'{"Results": []}')
        mock_exec = AsyncMock(return_value=proc)
        with patch("asyncio.create_subprocess_exec", mock_exec):
            await scanner.scan("node:22-alpine")

        args = list(mock_exec.call_args.args)
        assert "--cache-dir" in args
        assert args[args.index("--cache-dir") + 1] == str(tmp_path / "trivy")

    @pytest.mark.asyncio
    async def test_refresh_db_downloads_once_then_enables_skip(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        scanner = TrivyScanner(cache_dir=base, workers=4)
        proc = _FakeProc()
        mock_exec = AsyncMock(return_value=proc)
        with patch("asyncio.create_subprocess_exec", mock_exec):
            assert await scanner.refresh_db() is True

        assert mock_exec.await_count == 1
        args = list(mock_exec.call_args.args)
        assert "--download-db-only" in args
        assert args[args.index("--cache-dir") + 1] == str(base)
        assert scanner._skip_db_update is True
        # With the DB present, the pool built isolated per-worker dirs.
        assert scanner.cache_pool.isolated is True
        await scanner.close()

    @pytest.mark.asyncio
    async def test_scans_after_refresh_skip_db_update(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        scanner = TrivyScanner(cache_dir=base, workers=2)
        mock_exec = AsyncMock(return_value=_FakeProc(stdout=b'{"Results": []}'))
        with patch("asyncio.create_subprocess_exec", mock_exec):
            await scanner.refresh_db()
            await scanner.scan("node:22-alpine")

        args = list(mock_exec.call_args.args)
        assert "--skip-db-update" in args
        # The scan ran in an isolated slot, not the shared cache dir.
        assert args[args.index("--cache-dir") + 1] != str(base)
        await scanner.close()

    @pytest.mark.asyncio
    async def test_close_cleans_up_temp_dirs(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        scanner = TrivyScanner(cache_dir=base, workers=3)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=_FakeProc())):
            await scanner.refresh_db()

        dirs = list(scanner.cache_pool._temp_dirs)
        assert dirs
        await scanner.close()
        assert all(not d.exists() for d in dirs)
