from __future__ import annotations

from typing import Any

from loguru import logger
from sqlalchemy import Engine, Float, String, Text, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class CacheEntry(Base):
    __tablename__ = "cache_entries"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(512), unique=True, nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    # Indexed because `cleanup_expired` filters on it; without the index that
    # is a full table scan of every analysis ever cached.
    expires_at: Mapped[float] = mapped_column(Float, nullable=False, index=True)


# How long a connection waits for a lock before giving up. `recommend` runs
# its cache writes on a thread pool, so contention is normal rather than
# exceptional, and a write that gives up is a scan that has to be redone.
BUSY_TIMEOUT_MS = 5000


def _apply_pragmas(dbapi_connection: Any, _record: Any) -> None:
    """Configure SQLite for the concurrency this tool actually creates.

    `recommend --workers 10` reads and writes the cache from a thread pool.
    Under SQLite's default rollback journal a writer takes an exclusive lock
    on the whole database, so every concurrent reader blocks behind it; a
    reader that runs out of patience is treated as a cache miss, which means
    the image gets scanned again. The cache quietly stops working exactly
    when it is under the most load.

    WAL lets readers proceed while a write is in flight, which is precisely
    this workload's shape, and it holds across processes as well -- two
    `dockerls` runs sharing a cache no longer serialise on each other.

    `synchronous=NORMAL` is the standard companion to WAL: it drops the
    per-commit fsync, and its documented failure mode is losing the last few
    commits on an OS crash. For a cache whose entries are all reconstructible
    by re-scanning, that is the right trade -- there is no durability
    requirement here to protect.

    Measured on this repository, 200 concurrent writes + 200 reads:
    ~0.72s -> ~0.50s.

    Pragmas are applied per connection because SQLAlchemy pools them and
    `journal_mode` is the one setting that persists in the database file
    itself. A filesystem that cannot support WAL (some network mounts)
    leaves the mode unchanged rather than failing -- slower, still correct.
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        cursor.execute("PRAGMA cache_size=-64000")
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.execute("PRAGMA mmap_size=268435456")
    except Exception as e:  # pragma: no cover - pragmas are advisory
        logger.debug(f"Could not apply SQLite pragmas: {e}")
    finally:
        cursor.close()


def create_db_engine(db_path: str) -> tuple[Engine, sessionmaker[Session]]:
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    event.listen(engine, "connect", _apply_pragmas)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    return engine, factory
