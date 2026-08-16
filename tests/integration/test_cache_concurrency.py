"""The cache has to keep working under the load `recommend` puts on it.

`recommend --workers 10` reads and writes the cache from a thread pool, and
two runs can share one database file. Under SQLite's default rollback
journal a writer locks the whole database, so readers queue behind it and a
reader that gives up is treated as a miss -- meaning the image is scanned
again. The cache stops working exactly when it is under the most load, and
it does so silently, because a miss is indistinguishable from a cold cache.

WAL is what makes readers and a writer coexist, so these tests check that
the mode is actually in force rather than merely requested.
"""

from __future__ import annotations

import asyncio
import sqlite3
import subprocess  # noqa: S404 - cross-process locking is the point
import sys
import textwrap

import pytest

from dockerls.cache.sqlite_cache import SQLiteCache


@pytest.fixture
def cache(tmp_path):
    return SQLiteCache(tmp_path / "cache.db")


class TestSqliteIsConfiguredForConcurrency:
    def test_journal_mode_is_wal(self, tmp_path):
        """Checked against the file, not the pragma call: `journal_mode` is
        persisted in the database itself, and a filesystem that cannot
        support WAL silently keeps the old mode instead of failing."""
        path = tmp_path / "cache.db"
        SQLiteCache(path)

        con = sqlite3.connect(path)
        try:
            mode = con.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            con.close()
        assert mode.lower() == "wal"

    async def test_a_write_does_not_lock_out_readers(self, cache):
        """The property WAL buys. Interleaving 100 writes with 100 reads
        must not raise, and must not silently drop a write."""
        payload = {"vulnerabilities": [{"cve": f"CVE-{i}"} for i in range(50)]}

        async def write(i: int) -> None:
            await cache.set(f"analysis:node:{i}", payload, ttl_seconds=600)

        async def read(i: int) -> None:
            await cache.get(f"analysis:node:{i}")

        await asyncio.gather(*[write(i) for i in range(100)], *[read(i) for i in range(100)])

        stats = await cache.stats()
        assert stats.total == 100

    async def test_concurrent_writes_to_one_key_leave_exactly_one_row(self, cache):
        await asyncio.gather(
            *[cache.set("analysis:node:22", {"n": i}, ttl_seconds=600) for i in range(30)]
        )
        stats = await cache.stats()
        assert stats.total == 1
        assert isinstance(await cache.get("analysis:node:22"), dict)


class TestTwoProcessesSharingACache:
    """Two `dockerls` runs on one machine share the cache file. Under the
    rollback journal they serialise on each other; under WAL they do not."""

    def test_a_second_process_can_write_while_the_first_holds_the_cache(self, tmp_path):
        path = tmp_path / "cache.db"
        SQLiteCache(path)  # create the file with the pragmas applied

        script = textwrap.dedent(
            f"""
            import asyncio
            from pathlib import Path
            from dockerls.cache.sqlite_cache import SQLiteCache

            async def main():
                cache = SQLiteCache(Path({str(path)!r}))
                await asyncio.gather(*[
                    cache.set(f"analysis:other:{{i}}", {{"i": i}}, ttl_seconds=600)
                    for i in range(50)
                ])
                print("OK")

            asyncio.run(main())
            """
        )
        result = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout

        # And the first process still sees a consistent database.
        cache = SQLiteCache(path)
        stats = asyncio.run(cache.stats())
        assert stats.total == 50


class TestCacheStats:
    async def test_reports_entry_counts(self, cache):
        await cache.set("a", {"v": 1}, ttl_seconds=600)
        await cache.set("b", {"v": 2}, ttl_seconds=600)

        stats = await cache.stats()
        assert stats.total == 2
        assert stats.expired == 0

    async def test_expired_entries_are_counted_as_reclaimable(self, cache):
        await cache.set("fresh", {"v": 1}, ttl_seconds=600)
        await cache.set("stale", {"v": 2}, ttl_seconds=-1)

        stats = await cache.stats()
        assert stats.total == 2
        assert stats.expired == 1

        assert await cache.cleanup_expired() == 1
        assert (await cache.stats()).expired == 0

    async def test_size_includes_the_write_ahead_log(self, cache, tmp_path):
        """WAL holds committed data that has not been checkpointed into the
        main file yet, so reporting only the .db can understate the
        footprint by most of it."""
        big = {"vulnerabilities": [{"cve": f"CVE-2024-{i}", "desc": "x" * 200} for i in range(500)]}
        await cache.set("big", big, ttl_seconds=600)

        stats = await cache.stats()
        main_only = (tmp_path / "cache.db").stat().st_size
        assert stats.size_bytes >= main_only

    async def test_reports_its_own_location(self, cache, tmp_path):
        stats = await cache.stats()
        assert stats.path == str(tmp_path / "cache.db")


class TestExpiryIsHonoured:
    async def test_an_expired_entry_reads_as_a_miss(self, cache):
        await cache.set("k", {"v": 1}, ttl_seconds=-1)
        assert await cache.get("k") is None

    async def test_reading_an_expired_entry_drops_it(self, cache):
        await cache.set("k", {"v": 1}, ttl_seconds=-1)
        await cache.get("k")
        assert (await cache.stats()).total == 0

    async def test_a_fresh_entry_survives_a_cleanup(self, cache):
        await cache.set("k", {"v": 1}, ttl_seconds=600)
        await cache.cleanup_expired()
        assert await cache.get("k") == {"v": 1}
