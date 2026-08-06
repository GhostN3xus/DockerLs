from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from pathlib import Path

_UNSAFE_PATH_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def slugify_reference(reference: str) -> str:
    """Flatten an image reference into a single safe path segment.

    Deliberately collapses "/" and ":" instead of preserving them: the
    evidence directory must stay flat and inside its root, so a reference
    can never steer a write outside `.dockerls/scans/`.
    """
    slug = _UNSAFE_PATH_CHARS.sub("_", reference).strip("._-")
    return slug[:120] or "image"


# Backwards-compatible private alias.
_slugify = slugify_reference


class EvidenceStore:
    """Persists the raw JSON emitted by each scanner so any displayed score
    can be traced back to the exact scanner output it was derived from."""

    def __init__(self, root: Path):
        self._root = root

    @property
    def root(self) -> Path:
        return self._root

    async def record_scan(self, image_reference: str, scanner: str, raw: str) -> str:
        """Write one scanner's raw JSON output. Returns the file path, or an
        empty string when the evidence could not be persisted (evidence is
        an audit aid -- never a reason to fail a scan)."""
        return await asyncio.to_thread(self._record_scan_sync, image_reference, scanner, raw)

    def _record_scan_sync(self, image_reference: str, scanner: str, raw: str) -> str:
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S%f")
        name = f"{slugify_reference(image_reference)}__{slugify_reference(scanner)}__{stamp}.json"
        path = self._root / name
        try:
            self._root.mkdir(parents=True, exist_ok=True)
            path.write_text(raw, encoding="utf-8")
        except OSError as e:
            logger.warning(f"Could not persist scan evidence for {image_reference}: {e}")
            return ""
        return str(path)

    async def record_manifest(self, query: str, entries: list[dict[str, Any]]) -> str:
        """Write the score <-> evidence linkage for one `recommend` run."""
        return await asyncio.to_thread(self._record_manifest_sync, query, entries)

    def _record_manifest_sync(self, query: str, entries: list[dict[str, Any]]) -> str:
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S")
        path = self._root / f"{slugify_reference(query)}__manifest__{stamp}.json"
        payload = {
            "query": query,
            "generated_at": datetime.now(tz=UTC).isoformat(),
            "images": entries,
        }
        try:
            self._root.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        except OSError as e:
            logger.warning(f"Could not persist evidence manifest for {query}: {e}")
            return ""
        return str(path)
