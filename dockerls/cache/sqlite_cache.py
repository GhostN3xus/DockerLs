from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from dockerls.domain.interfaces.cache_store import CacheStoreInterface
from dockerls.infrastructure.database.models import CacheEntry, create_db_engine


class SQLiteCache(CacheStoreInterface):
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._engine, self._session_factory = create_db_engine(str(db_path))

    def _session(self) -> Session:
        return self._session_factory()

    async def get(self, key: str) -> Any | None:
        with self._session() as session:
            stmt = select(CacheEntry).where(CacheEntry.key == key)
            entry = session.execute(stmt).scalar_one_or_none()
            if entry is None:
                return None
            if entry.expires_at < time.time():
                session.delete(entry)
                session.commit()
                return None
            return json.loads(entry.value)

    async def set(self, key: str, value: Any, ttl_seconds: int = 86400) -> None:
        serialized = json.dumps(value, default=str)
        expires_at = time.time() + ttl_seconds
        with self._session() as session:
            stmt = select(CacheEntry).where(CacheEntry.key == key)
            existing = session.execute(stmt).scalar_one_or_none()
            if existing:
                existing.value = serialized
                existing.expires_at = expires_at
            else:
                session.add(CacheEntry(key=key, value=serialized, expires_at=expires_at))
            session.commit()

    async def delete(self, key: str) -> None:
        with self._session() as session:
            session.execute(delete(CacheEntry).where(CacheEntry.key == key))
            session.commit()

    async def clear(self) -> None:
        with self._session() as session:
            session.execute(delete(CacheEntry))
            session.commit()

    async def cleanup_expired(self) -> int:
        with self._session() as session:
            stmt = delete(CacheEntry).where(CacheEntry.expires_at < time.time())
            result = session.execute(stmt)
            session.commit()
            return result.rowcount  # type: ignore[return-value]
