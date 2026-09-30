"""Saved runs, addressable by an identifier -- never by a path.

Every `recommend` and `analyze` leaves a small JSON document behind, so that:

* a later run can say what changed (`run_diff`),
* `dockerls export --run <id>` can render the same result in another format
  **without scanning again**,
* a CI job can hand the `run_id` to another step instead of re-measuring.

Security properties, because these files feed exports and are read back:

* the id is a fixed, validated shape (`20260930T131500Z-1a2b3c4d`); it is
  joined to the store's own directory and to nothing else, so no value a user
  types can name a path outside it;
* files are written `0600` in a `0700` directory, atomically (write to a
  temporary sibling, then rename), so a reader never sees half a document and
  other local users never see one at all;
* every string in a saved document has been through the project redactor;
* on read the document is untrusted: it is size-limited, must parse, and must
  carry the expected schema, or it is treated as if it did not exist;
* only files that match the id pattern *inside this directory* are ever listed
  or pruned -- nothing else that happens to live there is touched.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger

from dockerls.infrastructure.redaction import redact_values

SCHEMA = "dockerls.run/1"

#: `YYYYMMDDTHHMMSSZ-` plus eight hex digits: sortable by time, unguessable
#: enough not to collide, and impossible to turn into a path.
RUN_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")

#: A run document is a few hundred KiB at most. Anything bigger is not one.
MAX_DOCUMENT_BYTES = 32 * 1024 * 1024

#: How many runs are kept. Older ones are pruned after a save.
DEFAULT_RETENTION = 50


def scope_of(document: dict[str, Any]) -> tuple[str, ...]:
    """What makes two runs comparable: the question, the platform and the filters.

    The profile and time budget are *not* part of it: they change how much was
    measured, not what was asked, and images are compared one by one anyway.
    """
    return (
        str(document.get("command", "")),
        str(document.get("query", "")).lower(),
        str(document.get("platform", "")),
        str(document.get("filters", "")),
    )


class InvalidRunIdError(ValueError):
    """The text is not a run identifier."""


def validate_run_id(value: str) -> str:
    text = value.strip()
    if not RUN_ID.fullmatch(text):
        raise InvalidRunIdError(
            "a run id looks like 20260930T131500Z-1a2b3c4d (it is printed by every run)"
        )
    return text


class RunStore:
    def __init__(self, root: Path, *, retention: int = DEFAULT_RETENTION) -> None:
        self._root = root
        self._retention = max(1, retention)

    @property
    def root(self) -> Path:
        return self._root

    @staticmethod
    def new_run_id(now: datetime | None = None) -> str:
        moment = (now or datetime.now(tz=UTC)).astimezone(UTC)
        return f"{moment.strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"

    def _path(self, run_id: str) -> Path:
        return self._root / f"{validate_run_id(run_id)}.json"

    def save(
        self,
        *,
        command: str,
        query: str,
        platform: str,
        filters: str,
        profile: str,
        completeness: str,
        result: dict[str, Any],
        summary: dict[str, Any],
        version: str,
        run_id: str | None = None,
    ) -> str:
        """Write a run and return its id, or "" when it could not be written.

        Saving is a convenience for later commands, never a reason to fail the
        run that produced the result.
        """
        identifier = run_id or self.new_run_id()
        document = redact_values(
            {
                "schema": SCHEMA,
                "run_id": identifier,
                "created_at": datetime.now(tz=UTC).isoformat(),
                "dockerls_version": version,
                "command": command,
                "query": query,
                "platform": platform,
                "filters": filters,
                "profile": profile,
                "completeness": completeness,
                "summary": summary,
                "result": result,
            }
        )
        try:
            self._root.mkdir(parents=True, exist_ok=True, mode=0o700)
            with contextlib.suppress(OSError):
                self._root.chmod(0o700)
            descriptor, temporary = tempfile.mkstemp(dir=self._root, prefix=".run-", suffix=".tmp")
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(document, handle, ensure_ascii=False, default=str, allow_nan=False)
                Path(temporary).chmod(0o600)
                Path(temporary).replace(self._path(identifier))
            except BaseException:
                with contextlib.suppress(OSError):
                    Path(temporary).unlink()
                raise
        except (OSError, ValueError) as e:
            logger.warning(f"Could not save run {identifier}: {e}")
            return ""
        self._prune()
        return identifier

    def load(self, run_id: str) -> dict[str, Any] | None:
        """The saved document for `run_id`, or None when absent or unusable.

        Raises `InvalidRunIdError` for something that is not an id at all --
        that is a usage error, distinct from "no such run".
        """
        path = self._path(run_id)
        try:
            if not path.is_file() or path.is_symlink():
                return None
            if path.stat().st_size > MAX_DOCUMENT_BYTES:
                logger.warning(f"Run {run_id} is larger than a run document can be; ignoring it")
                return None
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            logger.warning(f"Could not read run {run_id}: {e}")
            return None
        if not isinstance(document, dict) or document.get("schema") != SCHEMA:
            return None
        if document.get("run_id") != run_id.strip():
            return None
        return document

    def ids(self) -> list[str]:
        """Saved run ids, newest first. Only files that are runs."""
        try:
            names = [p.stem for p in self._root.glob("*.json") if RUN_ID.fullmatch(p.stem)]
        except OSError:
            return []
        return sorted(names, reverse=True)

    def previous_compatible(
        self, current: dict[str, Any], scope: tuple[str, ...]
    ) -> dict[str, Any] | None:
        """The most recent earlier run that asked the same question."""
        for run_id in self.ids():
            if run_id == current.get("run_id"):
                continue
            document = self.load(run_id)
            if document is not None and scope_of(document) == scope:
                return document
        return None

    def _prune(self) -> None:
        for stale in self.ids()[self._retention :]:
            with contextlib.suppress(OSError):
                self._path(stale).unlink()
