"""The shared, layered store behind every command that measures an image.

`analyze`, `compare`, `advisor`, `alternatives` and `recommend` all measure
images, and each used to keep (or not keep) its own idea of what a stored
result meant. Nothing could be reused between them, and the one cache that
existed stored a *finished analysis* -- policy, ignore rules and threat
intelligence baked into the same row as the scanner's raw output -- so
changing a threshold meant scanning again.

Four layers, each with its own key, lifetime and reason to be invalidated:

1. **scan** -- the scanner's normalised output for one immutable identity
   (registry, repository, *platform manifest digest*, platform), by one
   scanner at one version against one vulnerability-database revision, with
   one set of options. Invalidated by: a new database revision, a new scanner
   version, changed options, expiry.
2. **oci** -- what the registry said about a manifest: its verified config
   facts, keyed by the manifest digest and platform (long-lived, because
   content-addressed bytes never change). A tag -> identity mapping is
   deliberately *not* persisted: a tag is a moving pointer, and it is resolved
   once per run instead.
3. **intel** -- KEV / EPSS / OSV / Exploit-DB answers. Lives in the clients
   (per CVE, with its own TTLs); it is deliberately *not* stored in a scan
   row, so a feed update never needs a new scan.
4. **evaluation** -- score, tier and recommendation: derived, so it is keyed
   by the scan record *and* the policy that produced it. A different policy is
   a miss here and a hit one layer down.

Rules that hold for every read:

* the payload is untrusted -- schema, identity, scanner and options are
  re-validated *inside* the row, not inferred from the key it was stored
  under;
* corrupt, incompatible, expired or mismatched rows are **misses with a
  recorded reason**, never errors and never silently served;
* an incomplete scan (`PARTIAL`, `ERROR`, `TIMEOUT`) is never reusable as a
  complete analysis;
* a write failure never affects the scan that produced the data.

Only a *confirmed* identity may be stored (`ResolvedIdentity.confirmed`); a
result whose bytes were not pinned is reported to the user and never filed as
immutable evidence.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from loguru import logger
from pydantic import BaseModel, ValidationError

from dockerls.domain.entities.scan_result import ScanResult, ScanStatus

if TYPE_CHECKING:
    from collections.abc import Callable

    from dockerls.domain.interfaces.cache_store import CacheStoreInterface
    from dockerls.domain.value_objects.image_identity import ImageIdentity
    from dockerls.domain.value_objects.measured_identity import ResolvedIdentity

#: Bump when the *meaning* of a stored record changes.
SCHEMA_VERSION = 1

#: How long a raw scan stays reusable while its database revision is known
#: and unchanged. The revision, not the clock, is the real invalidator; this
#: is the backstop against a revision that never moves.
DEFAULT_SCAN_TTL_SECONDS = 24 * 3600

#: Conservative policy when the database revision cannot be determined: the
#: scan is reusable only for an hour, and only by a run that *also* cannot
#: tell. "Unknown" is never treated as "unchanged".
UNKNOWN_REVISION_TTL_SECONDS = 3600

#: Config facts are addressed by the digest of the manifest they describe.
FACTS_TTL_SECONDS = 7 * 24 * 3600

#: Enrichment older than this makes a cached *evaluation* stale even though
#: the scan underneath is still good.
INTEL_MAX_AGE_SECONDS = 6 * 3600

_MAX_DIAGNOSTICS = 50
_CANONICAL = re.compile(r"^sha256:[a-f0-9]{64}$")


class MissReason(StrEnum):
    ABSENT = "ABSENT"
    EXPIRED = "EXPIRED"
    CORRUPT = "CORRUPT"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    SCANNER_CHANGED = "SCANNER_CHANGED"
    OPTIONS_CHANGED = "OPTIONS_CHANGED"
    DB_REVISION_CHANGED = "DB_REVISION_CHANGED"
    DB_REVISION_UNKNOWN = "DB_REVISION_UNKNOWN"
    INCOMPLETE_SCAN = "INCOMPLETE_SCAN"
    UNCONFIRMED_IDENTITY = "UNCONFIRMED_IDENTITY"
    POLICY_CHANGED = "POLICY_CHANGED"
    ENRICHMENT_STALE = "ENRICHMENT_STALE"
    BYPASSED = "BYPASSED"
    UNREADABLE = "UNREADABLE"


@dataclass(frozen=True, slots=True)
class ScannerFingerprint:
    """Which measuring tool produced a scan, and what it knew when it did."""

    name: str
    version: str = ""
    #: When the vulnerability database in use was built. "" = unknown.
    db_revision: str = ""
    options: str = ""
    #: `(tool, version, database revision)` for each tool behind this scanner.
    #: A fallback scanner is two tools, and a result came from exactly one of
    #: them: provenance must report *that* tool's version and database, not a
    #: composite that no single measurement was made with.
    components: tuple[tuple[str, str, str], ...] = ()

    @property
    def revision_known(self) -> bool:
        return bool(self.db_revision)

    def component(self, tool: str) -> tuple[str, str] | None:
        """`(version, database revision)` of the tool named `tool`, if known."""
        for name, version, revision in self.components:
            if name == tool:
                return version, revision
        return None


@dataclass(frozen=True, slots=True)
class Lookup:
    """The answer to a read: a value, or a *named* reason there is none."""

    value: Any = None
    reason: MissReason | None = None
    detail: str = ""

    @property
    def hit(self) -> bool:
        return self.reason is None


class MeasurementRecord(BaseModel):
    """One stored scan, with everything needed to validate and explain it."""

    schema_version: int = SCHEMA_VERSION
    layer: str = "scan"
    registry: str
    repository: str
    digest: str
    platform: str
    index_digest: str = ""
    requested_reference: str = ""
    scanner: str
    scanner_version: str = ""
    db_revision: str = ""
    options: str = ""
    #: When the scanner ran (its own timestamp): what a reader is shown.
    measured_at: str
    #: When this row was written, on the store's clock: what expiry uses.
    stored_at: float = 0.0
    valid_until: float
    origin: str = "scan"
    scan: ScanResult


def _iso_now(clock: Callable[[], float]) -> str:
    return datetime.fromtimestamp(clock(), tz=UTC).isoformat()


class MeasurementStore:
    """Read/write access to the layers above over any `CacheStoreInterface`.

    Constructed with `cache=None` (`--no-cache`), every read is a `BYPASSED`
    miss and every write a no-op: the store then behaves exactly like the
    absence of a cache, which is what that flag has always meant.
    """

    def __init__(
        self,
        cache: CacheStoreInterface | None,
        *,
        scan_ttl_seconds: int = DEFAULT_SCAN_TTL_SECONDS,
        unknown_revision_ttl_seconds: int = UNKNOWN_REVISION_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._cache = cache
        self._scan_ttl = max(1, scan_ttl_seconds)
        self._unknown_ttl = max(1, unknown_revision_ttl_seconds)
        self._clock = clock
        #: Why reads missed, for the run's diagnostics (bounded).
        self.diagnostics: list[str] = []
        self.writes_failed = 0

    @property
    def enabled(self) -> bool:
        return self._cache is not None

    def _note(self, message: str) -> None:
        logger.debug(message)
        if len(self.diagnostics) < _MAX_DIAGNOSTICS:
            self.diagnostics.append(message)

    # ---- layer 1: raw scan -------------------------------------------------

    @staticmethod
    def _scan_key(identity: ImageIdentity, fingerprint: ScannerFingerprint) -> str:
        return f"m:scan:v{SCHEMA_VERSION}:{fingerprint.name}|{identity.cache_material}"

    async def get_scan(self, identity: ImageIdentity, fingerprint: ScannerFingerprint) -> Lookup:
        if self._cache is None:
            return Lookup(reason=MissReason.BYPASSED)
        key = self._scan_key(identity, fingerprint)
        try:
            raw = await self._cache.get(key)
        except Exception as e:
            self._note(f"cache unreadable for {identity.cache_material}: {e}")
            return Lookup(reason=MissReason.UNREADABLE, detail=str(e))
        if raw is None:
            return Lookup(reason=MissReason.ABSENT)

        lookup = self._validate_scan(raw, identity, fingerprint)
        if lookup.hit:
            return lookup
        self._note(
            f"cached scan for {identity.repository}@{identity.digest[:19]} not reused: "
            f"{lookup.reason.value if lookup.reason else ''} {lookup.detail}".rstrip()
        )
        if lookup.reason in (MissReason.CORRUPT, MissReason.SCHEMA_MISMATCH):
            await self._discard(key)
        return lookup

    def _validate_scan(
        self, raw: Any, identity: ImageIdentity, fingerprint: ScannerFingerprint
    ) -> Lookup:
        if not isinstance(raw, dict):
            return Lookup(reason=MissReason.CORRUPT, detail="payload is not an object")
        if raw.get("schema_version") != SCHEMA_VERSION or raw.get("layer") != "scan":
            return Lookup(reason=MissReason.SCHEMA_MISMATCH)
        try:
            record = MeasurementRecord.model_validate(raw)
        except ValidationError as e:
            return Lookup(reason=MissReason.CORRUPT, detail=f"{e.error_count()} invalid field(s)")

        stored = (record.registry, record.repository, record.digest, record.platform)
        wanted = (identity.registry, identity.repository, identity.digest, identity.platform)
        if stored != wanted or identity.digest not in record.scan.image_reference:
            return Lookup(
                reason=MissReason.IDENTITY_MISMATCH,
                detail="the row describes a different image than the key it was stored under",
            )
        if record.scan.status is not ScanStatus.OK or not record.scan.is_verified:
            return Lookup(reason=MissReason.INCOMPLETE_SCAN, detail=record.scan.status.value)
        if record.scanner != fingerprint.name or record.scanner_version != fingerprint.version:
            return Lookup(
                reason=MissReason.SCANNER_CHANGED,
                detail=f"{record.scanner} {record.scanner_version} -> "
                f"{fingerprint.name} {fingerprint.version}",
            )
        if record.options != fingerprint.options:
            return Lookup(reason=MissReason.OPTIONS_CHANGED)

        now = self._clock()
        if fingerprint.revision_known:
            if record.db_revision != fingerprint.db_revision:
                return Lookup(
                    reason=MissReason.DB_REVISION_CHANGED,
                    detail=f"{record.db_revision or 'unknown'} -> {fingerprint.db_revision}",
                )
        else:
            # Conservative: without a revision to compare, only a row that was
            # itself written without one, and only briefly, may be reused.
            fresh = 0 <= now - record.stored_at <= self._unknown_ttl
            if record.db_revision or not fresh:
                return Lookup(
                    reason=MissReason.DB_REVISION_UNKNOWN,
                    detail="the database revision cannot be determined, so the row is not trusted",
                )
        if record.valid_until < now:
            return Lookup(reason=MissReason.EXPIRED)
        return Lookup(value=record)

    async def put_scan(
        self,
        identity: ResolvedIdentity,
        fingerprint: ScannerFingerprint,
        scan: ScanResult,
        *,
        requested_reference: str,
        origin: str = "scan",
    ) -> bool:
        """Store a *complete* scan of a *confirmed* identity. Never raises.

        Returns whether a row was written. Refusing is normal, not an error:
        an unconfirmed identity or an incomplete scan is exactly what must not
        become reusable evidence.
        """
        strict = identity.identity
        if self._cache is None or strict is None:
            return False
        if scan.status is not ScanStatus.OK or not scan.is_verified:
            return False
        ttl = self._scan_ttl if fingerprint.revision_known else self._unknown_ttl
        record = MeasurementRecord(
            registry=strict.registry,
            repository=strict.repository,
            digest=strict.digest,
            platform=strict.platform,
            index_digest=identity.index_digest,
            requested_reference=requested_reference,
            scanner=fingerprint.name,
            scanner_version=fingerprint.version,
            db_revision=fingerprint.db_revision,
            options=fingerprint.options,
            measured_at=scan.scan_timestamp or _iso_now(self._clock),
            stored_at=self._clock(),
            valid_until=self._clock() + ttl,
            origin=origin,
            scan=scan,
        )
        try:
            await self._cache.set(
                self._scan_key(strict, fingerprint),
                record.model_dump(mode="json"),
                ttl_seconds=ttl,
            )
        except Exception as e:
            # The scan is done and correct; only the *reuse* is lost.
            self.writes_failed += 1
            self._note(f"could not store the scan of {strict.repository}: {e}")
            return False
        return True

    # ---- layer 2: registry metadata ---------------------------------------

    #: A digest names fixed bytes, so what it maps to for a platform never
    #: changes; the TTL only bounds how long unused rows linger.
    MAPPING_TTL_SECONDS = 30 * 24 * 3600

    @staticmethod
    def _mapping_key(host: str, repository: str, digest: str, platform: str) -> str:
        return f"m:oci:map:v{SCHEMA_VERSION}:{host}/{repository}@{digest}|{platform}"

    async def get_mapping(
        self, host: str, repository: str, digest: str, platform: str
    ) -> tuple[str, str] | None:
        """`(index digest, manifest digest)` verified earlier for `digest`.

        Untrusted on the way back: the row must say it is for exactly this
        digest and platform, and both digests it carries must be canonical --
        anything else is a miss.
        """
        if self._cache is None:
            return None
        try:
            raw = await self._cache.get(self._mapping_key(host, repository, digest, platform))
        except Exception:
            return None
        if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
            return None
        if raw.get("top_digest") != digest or raw.get("platform") != platform:
            return None
        index_digest = raw.get("index_digest", "")
        manifest_digest = raw.get("manifest_digest", "")
        if not isinstance(manifest_digest, str) or not _CANONICAL.fullmatch(manifest_digest):
            return None
        if not isinstance(index_digest, str) or (
            index_digest and not _CANONICAL.fullmatch(index_digest)
        ):
            return None
        return index_digest, manifest_digest

    async def put_mapping(
        self,
        host: str,
        repository: str,
        digest: str,
        platform: str,
        *,
        index_digest: str,
        manifest_digest: str,
    ) -> None:
        if self._cache is None:
            return
        body = {
            "schema_version": SCHEMA_VERSION,
            "top_digest": digest,
            "platform": platform,
            "index_digest": index_digest,
            "manifest_digest": manifest_digest,
        }
        try:
            await self._cache.set(
                self._mapping_key(host, repository, digest, platform),
                body,
                ttl_seconds=self.MAPPING_TTL_SECONDS,
            )
        except Exception as e:
            self.writes_failed += 1
            self._note(f"could not remember the mapping of {digest[:19]}: {e}")

    @staticmethod
    def _facts_key(digest: str, platform: str) -> str:
        return f"m:oci:facts:v{SCHEMA_VERSION}:{digest}|{platform}"

    async def get_facts(self, digest: str, platform: str) -> dict[str, Any] | None:
        """Config facts of an immutable manifest digest, or None."""
        if self._cache is None:
            return None
        try:
            raw = await self._cache.get(self._facts_key(digest, platform))
        except Exception:
            return None
        if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
            return None
        if raw.get("digest") != digest or raw.get("platform") != platform:
            return None
        facts = raw.get("facts")
        return facts if isinstance(facts, dict) else None

    async def put_facts(self, digest: str, platform: str, facts: dict[str, Any]) -> None:
        if self._cache is None:
            return
        body = {
            "schema_version": SCHEMA_VERSION,
            "digest": digest,
            "platform": platform,
            "facts": facts,
        }
        try:
            await self._cache.set(
                self._facts_key(digest, platform), body, ttl_seconds=FACTS_TTL_SECONDS
            )
        except Exception as e:
            self.writes_failed += 1
            self._note(f"could not store config facts for {digest[:19]}: {e}")

    # ---- layer 4: evaluation ----------------------------------------------

    @staticmethod
    def _evaluation_key(
        identity: ImageIdentity, fingerprint: ScannerFingerprint, policy: str
    ) -> str:
        return f"m:eval:v{SCHEMA_VERSION}:{fingerprint.name}|{policy}|{identity.cache_material}"

    async def get_evaluation(
        self, identity: ImageIdentity, fingerprint: ScannerFingerprint, policy: str
    ) -> Lookup:
        """A stored analysis for exactly this identity, scanner *and policy*.

        The scan record it was derived from is re-read and re-validated: an
        evaluation is only as good as the measurement under it, so a database
        update or an expired scan invalidates it too.
        """
        if self._cache is None:
            return Lookup(reason=MissReason.BYPASSED)
        scan_lookup = await self.get_scan(identity, fingerprint)
        if not scan_lookup.hit:
            return scan_lookup
        key = self._evaluation_key(identity, fingerprint, policy)
        try:
            raw = await self._cache.get(key)
        except Exception as e:
            return Lookup(reason=MissReason.UNREADABLE, detail=str(e))
        if raw is None:
            # The scan is reusable (checked above); only its evaluation under
            # *this* policy is missing, so a caller recomputes it -- no scan.
            return Lookup(reason=MissReason.POLICY_CHANGED)
        if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
            return Lookup(reason=MissReason.SCHEMA_MISMATCH)
        record: MeasurementRecord = scan_lookup.value
        if raw.get("scan_measured_at") != record.measured_at:
            return Lookup(
                reason=MissReason.EXPIRED, detail="the scan it was derived from was replaced"
            )
        intel_at = raw.get("intel_at")
        if isinstance(intel_at, int | float) and self._clock() - intel_at > INTEL_MAX_AGE_SECONDS:
            return Lookup(reason=MissReason.ENRICHMENT_STALE)
        payload = raw.get("analysis")
        return (
            Lookup(value=payload)
            if isinstance(payload, dict)
            else Lookup(reason=MissReason.CORRUPT)
        )

    async def put_evaluation(
        self,
        identity: ImageIdentity,
        fingerprint: ScannerFingerprint,
        policy: str,
        analysis: dict[str, Any],
        *,
        scan_measured_at: str,
        intel_at: float | None,
    ) -> None:
        if self._cache is None:
            return
        body = {
            "schema_version": SCHEMA_VERSION,
            "analysis": analysis,
            "scan_measured_at": scan_measured_at,
            "intel_at": intel_at,
        }
        try:
            await self._cache.set(
                self._evaluation_key(identity, fingerprint, policy),
                body,
                ttl_seconds=self._scan_ttl,
            )
        except Exception as e:
            self.writes_failed += 1
            self._note(f"could not store the evaluation of {identity.repository}: {e}")

    # ---- housekeeping ------------------------------------------------------

    async def _discard(self, key: str) -> None:
        """Drop one of *this application's* rows; failing to is harmless."""
        if self._cache is None:
            return
        try:
            await self._cache.delete(key)
        except Exception as e:
            self._note(f"could not evict {key}: {e}")
