from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

try:  # POSIX only; without it the pool cannot lease and serializes instead.
    import fcntl
except ImportError:  # pragma: no cover - exercised on non-POSIX platforms
    fcntl = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

_MARKER = ".dockerls-slot"
_SLOT_NAME = re.compile(r"^slot-(\d+)$")

#: A slot nobody has leased for this long is stale and may be removed.
DEFAULT_MAX_IDLE_SECONDS = 30 * 24 * 3600
#: What one slot may hold besides the (hard-linked) vulnerability DB.
DEFAULT_MAX_SLOT_BYTES = 1 << 30
#: What all slots may hold together, DB excluded.
DEFAULT_MAX_TOTAL_BYTES = 4 << 30


def default_trivy_cache_dir() -> Path:
    """Mirror Trivy's own default cache location resolution."""
    env = os.environ.get("TRIVY_CACHE_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / "trivy"
    return Path.home() / ".cache" / "trivy"


@dataclass(frozen=True)
class PoolStats:
    """What the pool actually did, for the run report -- not what it hoped to do."""

    mode: str  # "isolated" | "serialized"
    requested: int
    leased: int
    reason: str = ""


def _try_lock(path: Path, *, shared: bool = False) -> int | None:
    """Take a `flock` on `path` without blocking. The fd is the lease."""
    if fcntl is None:
        return None
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def _lock_blocking(path: Path, *, shared: bool) -> int | None:
    if fcntl is None:
        return None
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
    except OSError:
        os.close(fd)
        raise
    return fd


def _tree_bytes(path: Path, *, skip: str = "db") -> int:
    """Bytes under `path`, not counting the hard-linked `db/` directory."""
    total = 0
    for root, dirs, files in os.walk(path):
        if Path(root) == path and skip in dirs:
            dirs.remove(skip)
        for name in files:
            with contextlib.suppress(OSError):
                total += os.lstat(os.path.join(root, name)).st_size
    return total


class TrivyCachePool:
    """Persistent, leased ``--cache-dir`` slots for concurrent Trivy scans.

    Trivy takes an exclusive BoltDB lock on its cache directory, so parallel
    `trivy image` calls sharing one directory serialize on it and the losers
    time out. Each in-flight scan therefore gets a directory of its own.

    The slots are **persistent**: they live next to the shared cache, keep the
    layer cache (`fanal`) between runs, and so a second run does not start
    cold. Nothing mutable is ever shared between two processes:

    * a slot is used by one holder at a time, through an ``flock`` *lease* on
      ``slot-N.lock``. The kernel drops the lease when the holder dies, so a
      crash cannot strand a slot, and two concurrent DockerLs runs end up on
      different slots;
    * the vulnerability DB is **hard-linked** into a slot (a copy would
      multiply a multi-hundred-MB file by the worker count), and re-linked
      safely -- link to a temporary name, then atomic replace -- when the
      shared DB has been refreshed. The DB refresh takes an exclusive lease on
      ``db.lock`` and linking takes a shared one, so a slot never links a
      half-written DB.

    Storage is bounded: a slot over its byte limit is emptied when leased, and
    slots that are unleased and either stale or over the total limit are
    removed. Only directories that carry this pool's marker file and follow
    its naming are ever deleted; anything else in the parent belongs to
    someone else and is left alone.

    When no slot can be leased (no ``flock``, no DB yet, unwritable parent,
    every slot busy) the pool falls back to the shared cache directory and
    **serializes** scans. That is slower but correct, and ``stats`` says so.
    The number of concurrent scans never exceeds the workers requested.
    """

    _DB_FILES = ("trivy.db", "metadata.json")

    def __init__(
        self,
        base_cache_dir: Path,
        size: int,
        *,
        max_slot_bytes: int = DEFAULT_MAX_SLOT_BYTES,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_idle_seconds: float = DEFAULT_MAX_IDLE_SECONDS,
    ):
        self._base = base_cache_dir
        self._size = max(1, size)
        self._max_slot_bytes = max_slot_bytes
        self._max_total_bytes = max_total_bytes
        self._max_idle = max_idle_seconds
        self._root = base_cache_dir.parent / f"dockerls-slots-{base_cache_dir.name}"
        self._slots: asyncio.Queue[Path] | None = None
        # The list that feeds the queue, for callers that rotate themselves:
        # the Go engine is handed every slot at once.
        self._slot_paths: list[Path] = []
        self._leases: list[int] = []
        self._isolated = False
        self._reason = ""
        # prepare() awaits before assigning _slots; without the lock, the
        # first concurrent scans could each build a full pool.
        self._prepare_lock = asyncio.Lock()

    @property
    def isolated(self) -> bool:
        """True when each concurrent scan got its own cache directory."""
        return self._isolated

    @property
    def base_dir(self) -> Path:
        return self._base

    @property
    def stats(self) -> PoolStats:
        return PoolStats(
            mode="isolated" if self._isolated else "serialized",
            requested=self._size,
            leased=len(self._slot_paths) if self._isolated else 0,
            reason=self._reason,
        )

    # -- preparing ---------------------------------------------------------

    async def prepare(self) -> bool:
        """Build the slot pool. Returns True when isolation was achieved."""
        await self._ensure_slots()
        return self._isolated

    async def _ensure_slots(self) -> asyncio.Queue[Path]:
        if self._slots is not None:
            return self._slots
        async with self._prepare_lock:
            if self._slots is not None:
                return self._slots
            slots, reason = await asyncio.to_thread(self._lease_slots)
            if slots:
                self._isolated = True
                self._reason = reason  # non-empty when fewer slots than workers
            else:
                self._isolated = False
                self._reason = reason or "no slot could be leased"
                slots = [self._base]
            if self._reason:
                logger.warning(
                    f"Trivy cache: {self._reason}; "
                    + (
                        f"{len(slots)} of {self._size} scans can run at once"
                        if self._isolated
                        else "scans are serialized on the shared cache directory"
                    )
                )
            queue: asyncio.Queue[Path] = asyncio.Queue()
            for slot in slots:
                queue.put_nowait(slot)
            self._slot_paths = list(slots)
            self._slots = queue
            return queue

    def _lease_slots(self) -> tuple[list[Path], str]:
        if fcntl is None:
            return [], "file locking is unavailable on this platform"
        db_dir = self._base / "db"
        if not all((db_dir / name).exists() for name in self._DB_FILES):
            return [], f"no vulnerability DB under {db_dir} yet"
        try:
            self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as e:
            return [], f"cannot create {self._root}: {e}"

        # Enough room for other runs to hold theirs too.
        limit = max(self._size * 4, 16)
        slots: list[Path] = []
        with self._db_lease(shared=True):
            for index in range(limit):
                if len(slots) == self._size:
                    break
                path = self._root / f"slot-{index}"
                fd = _try_lock(self._root / f"slot-{index}.lock")
                if fd is None:
                    continue
                try:
                    self._prepare_slot(path)
                except OSError as e:
                    logger.warning(f"Trivy cache slot {path} unusable: {e}")
                    os.close(fd)
                    continue
                self._leases.append(fd)
                slots.append(path)
        with contextlib.suppress(OSError):
            self._prune(limit)
        if not slots:
            return [], "every cache slot is busy or unusable"
        if len(slots) < self._size:
            return slots, f"only {len(slots)} of {self._size} cache slots could be leased"
        return slots, ""

    def _prepare_slot(self, path: Path) -> None:
        path.mkdir(mode=0o700, exist_ok=True)
        marker = path / _MARKER
        if not marker.exists():
            marker.write_text("dockerls trivy cache slot\n")
        if _tree_bytes(path) > self._max_slot_bytes:
            logger.info(f"Trivy cache slot {path.name} over its limit; emptying it")
            self._empty_slot(path)
        self._relink_db(path)
        os.utime(path)  # marks it as recently used, for the staleness rule

    @staticmethod
    def _empty_slot(path: Path) -> None:
        for child in path.iterdir():
            if child.name == _MARKER:
                continue
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                with contextlib.suppress(OSError):
                    child.unlink()

    def _relink_db(self, slot: Path) -> None:
        """Hard-link the shared DB into `slot`, atomically and only if it differs."""
        (slot / "db").mkdir(exist_ok=True)
        for name in self._DB_FILES:
            src = self._base / "db" / name
            dst = slot / "db" / name
            try:
                if dst.exists() and os.path.samestat(src.stat(), dst.stat()):
                    continue
            except OSError:
                pass
            tmp = dst.with_name(f"{name}.link-{os.getpid()}")
            with contextlib.suppress(OSError):
                tmp.unlink()
            os.link(src, tmp)
            os.replace(tmp, dst)

    # -- the shared DB -----------------------------------------------------

    @contextlib.contextmanager
    def _db_lease(self, *, shared: bool) -> Iterator[None]:
        fd = None
        try:
            self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = _lock_blocking(self._root / "db.lock", shared=shared)
        except OSError as e:
            logger.debug(f"Trivy DB lease unavailable ({e}); continuing without it")
        try:
            yield
        finally:
            if fd is not None:
                os.close(fd)

    @contextlib.asynccontextmanager
    async def db_refresh_lease(self) -> AsyncIterator[None]:
        """Exclusive lease held while the shared DB is being downloaded.

        Held across the download, so no other run links a half-written DB and
        two runs do not refresh at once. Blocks (in a thread) until the
        leases of runs that are linking the DB are released -- which is quick.
        """

        def acquire() -> int | None:
            try:
                self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
                return _lock_blocking(self._root / "db.lock", shared=False)
            except OSError as e:
                logger.debug(f"Trivy DB refresh lease unavailable ({e}); continuing without it")
                return None

        fd = await asyncio.to_thread(acquire)
        try:
            yield
        finally:
            if fd is not None:
                os.close(fd)

    # -- storage limits ----------------------------------------------------

    def _prune(self, keep_below: int) -> None:
        """Remove this pool's own unleased slots that are stale or over the limit."""
        entries: list[tuple[float, int, Path, int]] = []
        for child in self._root.iterdir():
            match = _SLOT_NAME.match(child.name)
            if not match or not child.is_dir() or child.is_symlink():
                continue
            if not (child / _MARKER).is_file():
                continue  # not ours to touch
            index = int(match.group(1))
            try:
                entries.append((child.stat().st_mtime, index, child, _tree_bytes(child)))
            except OSError:
                continue
        now = time.time()
        total = sum(size for *_, size in entries)
        for mtime, index, path, size in sorted(entries):  # oldest first
            stale = now - mtime > self._max_idle or index >= keep_below
            if not stale and total <= self._max_total_bytes:
                continue
            if self._remove_if_unleased(path, index):
                total -= size

    def _remove_if_unleased(self, path: Path, index: int) -> bool:
        lock = self._root / f"slot-{index}.lock"
        fd = _try_lock(lock)
        if fd is None:
            return False  # someone is using it
        try:
            shutil.rmtree(path, ignore_errors=True)
            with contextlib.suppress(OSError):
                lock.unlink()
            return not path.exists()
        finally:
            os.close(fd)

    # -- using -------------------------------------------------------------

    async def slot_paths(self) -> list[Path]:
        """Every slot of the pool, for a caller that rotates them itself.

        `acquire()` lends one at a time, which is what the Python pipeline
        needs. The Go engine receives the whole batch and rotates inside.
        """
        await self._ensure_slots()
        return list(self._slot_paths)

    @contextlib.asynccontextmanager
    async def acquire(self) -> AsyncIterator[Path]:
        slots = await self._ensure_slots()
        slot = await slots.get()
        try:
            yield slot
        finally:
            slots.put_nowait(slot)

    async def cleanup(self) -> None:
        """Release the leases and enforce the storage limits.

        The slots themselves stay: keeping the layer cache is what persisting
        them is for. The shared cache directory and its DB are never touched.
        """
        leases, self._leases = self._leases, []
        for fd in leases:
            with contextlib.suppress(OSError):
                os.close(fd)
        if self._slot_paths and self._isolated:
            await asyncio.to_thread(self._enforce_limits_after_release)

    def _enforce_limits_after_release(self) -> None:
        with contextlib.suppress(OSError):
            self._prune(max(self._size * 4, 16))
