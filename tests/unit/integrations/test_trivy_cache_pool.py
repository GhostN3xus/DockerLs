from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
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
    async def test_slots_are_distinct_and_never_the_shared_dir(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        pool = TrivyCachePool(base, size=3)
        assert await pool.prepare() is True
        slots = await pool.slot_paths()
        assert len({str(s) for s in slots}) == 3
        assert all(s != base for s in slots)
        await pool.cleanup()

    @pytest.mark.asyncio
    async def test_single_worker_also_gets_its_own_slot(self, tmp_path):
        """No mutable file is shared, even when there is one worker: another
        DockerLs run may be using the shared directory."""
        base = _seed_db(tmp_path / "trivy")
        pool = TrivyCachePool(base, size=1)
        assert await pool.prepare() is True
        async with pool.acquire() as slot:
            assert slot != base
        await pool.cleanup()

    @pytest.mark.asyncio
    async def test_db_is_hardlinked_not_copied(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        pool = TrivyCachePool(base, size=2)
        await pool.prepare()
        source = base / "db" / "trivy.db"
        for slot in await pool.slot_paths():
            assert (slot / "db" / "trivy.db").stat().st_ino == source.stat().st_ino
        await pool.cleanup()

    @pytest.mark.asyncio
    async def test_relinks_a_refreshed_db_on_the_next_run(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        first = TrivyCachePool(base, size=1)
        await first.prepare()
        await first.cleanup()

        # Trivy replaces the file: a new inode, the old one stays where it was.
        new = base / "db" / "trivy.db.new"
        new.write_bytes(b"refreshed-db")
        new.replace(base / "db" / "trivy.db")

        second = TrivyCachePool(base, size=1)
        await second.prepare()
        (slot,) = await second.slot_paths()
        assert (slot / "db" / "trivy.db").read_bytes() == b"refreshed-db"
        assert (slot / "db" / "trivy.db").stat().st_ino == (base / "db" / "trivy.db").stat().st_ino
        assert not list((slot / "db").glob("*.link-*"))
        await second.cleanup()

    @pytest.mark.asyncio
    async def test_missing_db_serializes_visibly(self, tmp_path):
        base = tmp_path / "trivy"
        base.mkdir()
        pool = TrivyCachePool(base, size=4)
        assert await pool.prepare() is False
        assert pool.stats.mode == "serialized"
        assert "vulnerability DB" in pool.stats.reason
        async with pool.acquire() as slot:
            assert slot == base

    @pytest.mark.asyncio
    async def test_serialized_pool_runs_one_scan_at_a_time(self, tmp_path):
        base = tmp_path / "trivy"
        base.mkdir()
        pool = TrivyCachePool(base, size=4)
        await pool.prepare()
        in_flight = peak = 0

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
        in_flight = peak = 0

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
    async def test_concurrent_first_acquire_builds_one_pool(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        pool = TrivyCachePool(base, size=3)

        async def use():
            async with pool.acquire():
                await asyncio.sleep(0)

        await asyncio.gather(*[use() for _ in range(5)])
        assert len(pool._slot_paths) == 3
        assert pool._slots.qsize() == 3
        await pool.cleanup()

    @pytest.mark.asyncio
    async def test_two_runs_at_once_never_share_a_slot(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        a = TrivyCachePool(base, size=3)
        b = TrivyCachePool(base, size=3)
        await a.prepare()
        await b.prepare()
        mine, theirs = await a.slot_paths(), await b.slot_paths()
        assert not {str(p) for p in mine} & {str(p) for p in theirs}
        assert a.stats.leased == 3 and b.stats.leased == 3
        await a.cleanup()
        await b.cleanup()

    @pytest.mark.asyncio
    async def test_when_every_slot_is_busy_it_serializes_and_says_so(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        holder = TrivyCachePool(base, size=16)
        await holder.prepare()  # takes all 16 of the 16 it may scan
        # Fill up to the pool's own ceiling of slot indexes.
        limit = max(2 * 4, 16)
        assert limit == 16
        other = TrivyCachePool(base, size=2)
        assert await other.prepare() is False
        assert other.stats.mode == "serialized"
        assert "busy" in other.stats.reason
        async with other.acquire() as slot:
            assert slot == base
        await holder.cleanup()

    @pytest.mark.asyncio
    async def test_fewer_slots_than_workers_reduces_concurrency_visibly(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        holder = TrivyCachePool(base, size=15)
        await holder.prepare()
        other = TrivyCachePool(base, size=4)  # ceiling 16, only one slot left
        assert await other.prepare() is True
        assert other.stats.leased == 1
        assert "only 1 of 4" in other.stats.reason
        await holder.cleanup()
        await other.cleanup()

    @pytest.mark.asyncio
    async def test_slots_persist_and_keep_their_layer_cache(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        first = TrivyCachePool(base, size=1)
        await first.prepare()
        (slot,) = await first.slot_paths()
        (slot / "fanal").mkdir()
        (slot / "fanal" / "fanal.db").write_bytes(b"layers")
        await first.cleanup()

        assert slot.exists()  # cleanup releases, it does not delete
        second = TrivyCachePool(base, size=1)
        await second.prepare()
        assert await second.slot_paths() == [slot]
        assert (slot / "fanal" / "fanal.db").read_bytes() == b"layers"
        await second.cleanup()

    @pytest.mark.asyncio
    async def test_cleanup_releases_leases_and_keeps_the_shared_db(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        pool = TrivyCachePool(base, size=2)
        await pool.prepare()
        await pool.cleanup()
        await pool.cleanup()  # idempotent
        assert (base / "db" / "trivy.db").exists()
        again = TrivyCachePool(base, size=2)
        await again.prepare()
        assert again.stats.leased == 2  # the leases really were released
        await again.cleanup()

    @pytest.mark.asyncio
    async def test_slot_over_its_limit_is_emptied_but_not_its_db(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        first = TrivyCachePool(base, size=1)
        await first.prepare()
        (slot,) = await first.slot_paths()
        (slot / "fanal").mkdir()
        (slot / "fanal" / "big").write_bytes(b"x" * 4096)
        await first.cleanup()

        small = TrivyCachePool(base, size=1, max_slot_bytes=1024)
        await small.prepare()
        assert not (slot / "fanal").exists()
        assert (slot / "db" / "trivy.db").exists()
        await small.cleanup()

    @pytest.mark.asyncio
    async def test_prune_removes_only_own_unleased_stale_slots(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        setup = TrivyCachePool(base, size=1)
        await setup.prepare()
        root = setup._root
        await setup.cleanup()

        stale = root / "slot-7"
        stale.mkdir()
        (stale / ".dockerls-slot").write_text("x")
        (stale / "junk").write_bytes(b"1")
        stranger = root / "slot-8"  # right name, no marker: not ours
        stranger.mkdir()
        (stranger / "keep-me").write_text("someone else's")
        leased = root / "slot-9"
        leased.mkdir()
        (leased / ".dockerls-slot").write_text("x")
        os.utime(stale, (0, 0))
        os.utime(leased, (0, 0))

        import fcntl

        fd = os.open(root / "slot-9.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            pool = TrivyCachePool(base, size=1, max_idle_seconds=60)
            await pool.prepare()
            await pool.cleanup()
        finally:
            os.close(fd)

        assert not stale.exists()
        assert (stranger / "keep-me").exists()
        assert leased.exists()  # in use by someone: untouched
        assert (base / "db" / "trivy.db").exists()

    @pytest.mark.asyncio
    async def test_total_storage_limit_evicts_oldest_unleased_first(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        setup = TrivyCachePool(base, size=1)
        await setup.prepare()
        root = setup._root
        await setup.cleanup()
        for i, age in ((5, 300), (6, 200)):
            d = root / f"slot-{i}"
            d.mkdir()
            (d / ".dockerls-slot").write_text("x")
            (d / "data").write_bytes(b"x" * 2000)
            os.utime(d, (time.time() - age, time.time() - age))
        pool = TrivyCachePool(base, size=1, max_total_bytes=2500)
        await pool.prepare()
        await pool.cleanup()
        assert not (root / "slot-5").exists()
        assert (root / "slot-6").exists()

    @pytest.mark.asyncio
    async def test_refresh_lease_excludes_linking(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        pool = TrivyCachePool(base, size=1)
        order: list[str] = []

        async def linker():
            await asyncio.sleep(0.05)
            await pool.prepare()  # needs the shared lease -> waits for the refresh
            order.append("linked")

        async with pool.db_refresh_lease():
            task = asyncio.create_task(linker())
            await asyncio.sleep(0.3)
            order.append("refreshed")
        await task
        assert order == ["refreshed", "linked"]
        await pool.cleanup()

    def test_parallel_processes_never_lease_the_same_slot(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        code = (
            "import asyncio, sys, time\n"
            "from pathlib import Path\n"
            "from dockerls.integrations.trivy.cache_pool import TrivyCachePool\n"
            "async def main():\n"
            "    p = TrivyCachePool(Path(sys.argv[1]), 3)\n"
            "    await p.prepare()\n"
            "    print(','.join(sorted(x.name for x in await p.slot_paths())), flush=True)\n"
            "    time.sleep(1.5)\n"
            "    await p.cleanup()\n"
            "asyncio.run(main())\n"
        )
        procs = [
            subprocess.Popen(  # noqa: S603 - fixed argv, test-only
                [sys.executable, "-c", code, str(base)], stdout=subprocess.PIPE, text=True
            )
            for _ in range(3)
        ]
        leased = [set(p.communicate(timeout=60)[0].strip().split(",")) for p in procs]
        assert all(len(s) == 3 for s in leased)
        assert not (leased[0] & leased[1] or leased[0] & leased[2] or leased[1] & leased[2])


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
    async def test_close_releases_the_leases_but_keeps_the_slots(self, tmp_path):
        base = _seed_db(tmp_path / "trivy")
        scanner = TrivyScanner(cache_dir=base, workers=3)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=_FakeProc())):
            await scanner.refresh_db()

        dirs = await scanner.cache_pool.slot_paths()
        assert dirs
        await scanner.close()
        assert all(d.exists() for d in dirs)
        again = TrivyCachePool(base, size=3)
        await again.prepare()
        assert again.stats.leased == 3
        await again.cleanup()
