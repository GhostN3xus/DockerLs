from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any, cast

from sqlalchemy import CursorResult, delete, select

from dockerls.domain.interfaces.cache_store import CacheStoreInterface
from dockerls.infrastructure.database.models import CacheEntry, create_db_engine

if TYPE_CHECKING:
    from pathlib import Path

    from sqlalchemy.orm import Session

# Bump this when the shape of cached payloads changes so stale entries from
# an older schema are treated as misses instead of crashing on load.
# v2: ImageAnalysis gained verification metadata (scan evidence paths, Hub
# tag state, scanner divergence) and ScanResult gained `evidence_path`.
CACHE_SCHEMA_VERSION = "v2"


class SQLiteCache(CacheStoreInterface):
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._engine, self._session_factory = create_db_engine(str(db_path))

    def _session(self) -> Session:
        return self._session_factory()

    def _versioned_key(self, key: str) -> str:
        return f"{CACHE_SCHEMA_VERSION}:{key}"

    async def get(self, key: str) -> Any | None:
        return await asyncio.to_thread(self._get_sync, key)

    def _get_sync(self, key: str) -> Any | None:
        vkey = self._versioned_key(key)
        with self._session() as session:
            stmt = select(CacheEntry).where(CacheEntry.key == vkey)
            entry = session.execute(stmt).scalar_one_or_none()
            if entry is None:
                return None
            if entry.expires_at < time.time():
                session.delete(entry)
                session.commit()
                return None
            return json.loads(entry.value)

    async def set(self, key: str, value: Any, ttl_seconds: int = 86400) -> None:
        await asyncio.to_thread(self._set_sync, key, value, ttl_seconds)

    def _set_sync(self, key: str, value: Any, ttl_seconds: int) -> None:
        vkey = self._versioned_key(key)
        serialized = json.dumps(value, default=str)
        expires_at = time.time() + ttl_seconds
        with self._session() as session:
            stmt = select(CacheEntry).where(CacheEntry.key == vkey)
            existing = session.execute(stmt).scalar_one_or_none()
            if existing:
                existing.value = serialized
                existing.expires_at = expires_at
            else:
                session.add(CacheEntry(key=vkey, value=serialized, expires_at=expires_at))
            session.commit()

    async def delete(self, key: str) -> None:
        await asyncio.to_thread(self._delete_sync, key)

    def _delete_sync(self, key: str) -> None:
        vkey = self._versioned_key(key)
        with self._session() as session:
            session.execute(delete(CacheEntry).where(CacheEntry.key == vkey))
            session.commit()

    async def clear(self) -> None:
        await asyncio.to_thread(self._clear_sync)

    def _clear_sync(self) -> None:
        with self._session() as session:
            session.execute(delete(CacheEntry))
            session.commit()

    async def cleanup_expired(self) -> int:
        return await asyncio.to_thread(self._cleanup_expired_sync)

    def _cleanup_expired_sync(self) -> int:
        with self._session() as session:
            stmt = delete(CacheEntry).where(CacheEntry.expires_at < time.time())
            result = cast("CursorResult[Any]", session.execute(stmt))
            session.commit()
            return result.rowcount
