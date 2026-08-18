from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from loguru import logger

from dockerls.infrastructure.redaction import redact

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
            # Redacted on the way to disk, with the same patterns the log
            # sink uses. A raw scan artifact is the file people attach to
            # tickets and paste into chats, and a scanner that fails an
            # authenticated pull echoes the request it attempted -- headers
            # included. Masking logs but not evidence covered the door
            # nobody walks through.
            path.write_text(redact(raw), encoding="utf-8")
        except OSError as e:
            logger.warning(f"Could not persist scan evidence for {image_reference}: {e}")
            return ""
        return str(path)

    async def record_manifest(
        self,
        query: str,
        entries: list[dict[str, Any]],
        provenance: dict[str, Any] | None = None,
    ) -> str:
        """Write the score <-> evidence linkage for one `recommend` run."""
        return await asyncio.to_thread(self._record_manifest_sync, query, entries, provenance)

    def _record_manifest_sync(
        self,
        query: str,
        entries: list[dict[str, Any]],
        provenance: dict[str, Any] | None = None,
    ) -> str:
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S")
        path = self._root / f"{slugify_reference(query)}__manifest__{stamp}.json"
        payload = {
            "query": query,
            "generated_at": datetime.now(tz=UTC).isoformat(),
            # What produced these numbers: which DockerLs, which scanner at
            # which version, and the fingerprint the cache was keyed on. An
            # analysis nobody can reconstruct is an assertion, not evidence,
            # and until this block existed the manifest recorded the verdict
            # without recording what reached it.
            "provenance": provenance or {},
            "images": entries,
        }
        try:
            self._root.mkdir(parents=True, exist_ok=True)
            path.write_text(redact(json.dumps(payload, indent=2, default=str)), encoding="utf-8")
        except OSError as e:
            logger.warning(f"Could not persist evidence manifest for {query}: {e}")
            return ""
        return str(path)
