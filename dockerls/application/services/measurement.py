"""The one place an image gets measured.

Every command that needs findings for an image asks this service, so the rules
that make a measurement *mean* something live in exactly one place:

1. **Pin the identity first.** A tag is resolved -- once per run -- to the
   digest of the manifest for the requested platform. The scanner is then
   handed ``name@sha256:...``, never the tag, so a tag that moves a moment
   later cannot make the result describe different bytes than the digest it is
   filed under. The requested, resolved and measured references stay separate.
2. **Reuse before spending.** A valid stored scan for the same identity,
   scanner, database revision and options is served instead of a new one (see
   `measurement_store`), with the reason logged when it is not.
3. **Never do the same work twice, never do unbounded work.** Concurrent
   requests for one identity share a single scan; the number of scans in
   flight is capped; the run's deadline is checked before a scan starts and
   cancels it (and its subprocess) when it runs out.
4. **Say what was not established.** An identity the registry did not confirm
   is still measured and reported -- with the limitation stated -- but is
   never stored as immutable evidence.

Nothing here scores, ranks or enriches: it produces a raw, normalised scan and
the provenance that goes with it.
"""

from __future__ import annotations

import asyncio
import inspect
import re
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

from loguru import logger

from dockerls.application.dto.analysis import MeasurementProvenance
from dockerls.application.services.measurement_store import (
    MeasurementStore,
    MissReason,
    ScannerFingerprint,
)
from dockerls.application.services.single_flight import SingleFlight
from dockerls.domain.entities.scan_result import ScanErrorKind, ScanResult, ScanStatus
from dockerls.domain.value_objects.measured_identity import (
    IdentityStatus,
    ImageRefs,
    ResolvedIdentity,
)
from dockerls.domain.value_objects.platform import DEFAULT_PLATFORM, Platform
from dockerls.utils.deadline import Deadline, DeadlineExceededError, run_within

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from dockerls.application.services.instrumentation import RunInstrumentation
    from dockerls.domain.entities.image import DockerImage
    from dockerls.domain.interfaces.scanner import ScannerInterface

#: A scan started with less than this left would only produce a killed
#: subprocess and a TIMEOUT that says nothing about the image.
MIN_SCAN_SECONDS = 5.0

#: Default cap on scans in flight from one service. Each is a scanner
#: process that wants a core and hundreds of megabytes; callers pass the
#: machine-derived worker count, this is only the floor for a bare service.
DEFAULT_CONCURRENCY = 2

#: Identity resolution is a couple of small HTTP requests, so it is bounded
#: separately (and more generously) than scans.
IDENTITY_CONCURRENCY = 8

_PINNED = re.compile(r"@(sha256:[a-f0-9]{64})$", re.IGNORECASE)


class IdentityResolver(Protocol):
    async def resolve_identity(
        self, name: str, tag: str, digest: str = "", platform: Platform | None = None
    ) -> ResolvedIdentity: ...


@dataclass(frozen=True)
class Measurement:
    """One image's raw scan plus how it was obtained."""

    scan: ScanResult
    identity: ResolvedIdentity
    refs: ImageRefs
    provenance: MeasurementProvenance
    from_cache: bool = False
    #: Joined a scan another task in this run had already started.
    shared: bool = False

    @property
    def stored_as_evidence(self) -> bool:
        """Whether this result is eligible to be reused later as pinned evidence."""
        return self.identity.confirmed and self.scan.is_verified


@dataclass
class MeasurementStats:
    scans_performed: int = 0
    cache_hits: int = 0
    duplicates_avoided: int = 0
    identities_resolved: int = 0
    identities_unconfirmed: int = 0
    not_started_deadline: int = 0
    queue_wait_seconds: float = 0.0


def _user_pinned_digest(image: DockerImage) -> str:
    """The digest the *user* wrote in the reference, or "".

    `DockerImage.digest` may also be a hint from a discovery source, which is
    exactly what identity resolution exists to verify -- so only a digest that
    is part of the requested reference counts as pinned by the user.
    """
    text = image.requested_reference or image.full_reference
    match = _PINNED.search(text)
    return match.group(1).lower() if match else ""


def _accepts_platform(scanner: ScannerInterface) -> bool:
    try:
        parameters = inspect.signature(scanner.scan).parameters
    except (TypeError, ValueError):  # pragma: no cover - builtins/C callables
        return False
    return "platform" in parameters or any(
        p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values()
    )


def scanner_kind(scanner: object) -> str:
    """A stable, lowercase name for a scanner, for cache namespaces."""
    primary = getattr(scanner, "primary", None)
    secondary = getattr(scanner, "secondary", None)
    if primary is not None and secondary is not None:
        return f"{scanner_kind(primary)}+{scanner_kind(secondary)}"
    name = type(scanner).__name__.lower()
    for known in ("trivy", "grype"):
        if known in name:
            return known
    return name


class MeasurementService:
    def __init__(
        self,
        scanner: ScannerInterface,
        *,
        resolver: IdentityResolver | None = None,
        store: MeasurementStore | None = None,
        platform: Platform = DEFAULT_PLATFORM,
        max_concurrency: int = DEFAULT_CONCURRENCY,
        deadline: Deadline | None = None,
        instrumentation: RunInstrumentation | None = None,
        min_scan_seconds: float = MIN_SCAN_SECONDS,
        stage: str = "scan_primary",
    ) -> None:
        self._scanner = scanner
        self._resolver = resolver
        self._store = store or MeasurementStore(None)
        self._platform = platform
        self._deadline = deadline or Deadline.unbounded()
        self._instrumentation = instrumentation
        self._min_scan_seconds = min_scan_seconds
        self._stage = stage
        self._max_concurrency = max(1, max_concurrency)
        self._scan_slots = asyncio.Semaphore(self._max_concurrency)
        self._resolve_slots = asyncio.Semaphore(IDENTITY_CONCURRENCY)
        self._scan_flight: SingleFlight[Measurement] = SingleFlight()
        self._identity_flight: SingleFlight[ResolvedIdentity] = SingleFlight()
        self._prepare_flight: SingleFlight[bool] = SingleFlight()
        self._finished: dict[tuple[str, ...], Measurement] = {}
        self._fingerprint: ScannerFingerprint | None = None
        self._accepts_platform = _accepts_platform(scanner)
        self.stats = MeasurementStats()

    # ---- properties --------------------------------------------------------

    @property
    def platform(self) -> Platform:
        return self._platform

    @property
    def store(self) -> MeasurementStore:
        return self._store

    @property
    def scanner(self) -> ScannerInterface:
        return self._scanner

    @property
    def max_concurrency(self) -> int:
        return self._max_concurrency

    # ---- preparation -------------------------------------------------------

    async def prepare(self, on_attempt: Callable[[int, int], None] | None = None) -> bool:
        """Refresh the scanner's database once, then fingerprint the scanner.

        Shared between callers: however many tasks ask, the database is
        refreshed by one of them. The fingerprint is read *after* the refresh,
        because the refresh is what changes the database revision.
        """
        ready, _ = await self._prepare_flight.run("prepare", lambda: self._prepare(on_attempt))
        return ready

    async def _prepare(self, on_attempt: Callable[[int, int], None] | None) -> bool:
        ready = True
        refresh = getattr(self._scanner, "refresh_db", None)
        if callable(refresh):
            started = time.monotonic()
            try:
                try:
                    ready = bool(await refresh(on_attempt=on_attempt))
                except TypeError:
                    # A refresh_db that takes no callback (Grype, the fallback
                    # scanner, a test double) -- an incompatible signature is
                    # not a scanner failure.
                    ready = bool(await refresh())
            finally:
                if self._instrumentation is not None:
                    self._instrumentation.add("database_preparation", time.monotonic() - started)
        await self.fingerprint()
        return ready

    async def fingerprint(self) -> ScannerFingerprint:
        if self._fingerprint is not None:
            return self._fingerprint
        version = await _text(self._scanner, "version")
        revision = await _text(self._scanner, "db_revision")
        options = await _text(self._scanner, "options")
        self._fingerprint = ScannerFingerprint(
            name=scanner_kind(self._scanner),
            version=version or "unknown-version",
            db_revision=revision,
            options=options,
        )
        return self._fingerprint

    # ---- identity ----------------------------------------------------------

    async def resolve(self, image: DockerImage) -> ResolvedIdentity:
        """Pin `image` to one platform manifest, once per run, and record it on
        the image (never touching its tag or display reference)."""
        digest = _user_pinned_digest(image)
        key = ("identity", image.name.lower(), image.tag, digest, str(self._platform))

        async def resolve_once() -> ResolvedIdentity:
            return await self._resolve_once(image, digest)

        identity, _ = await self._identity_flight.run(key, resolve_once)
        self._apply_identity(image, identity, digest)
        return identity

    async def _resolve_once(self, image: DockerImage, digest: str) -> ResolvedIdentity:
        base = ResolvedIdentity(
            name=image.name,
            tag=image.tag,
            platform=self._platform,
            status=IdentityStatus.DIGEST_ONLY if digest else IdentityStatus.UNRESOLVED,
            manifest_digest="",
            limitation="no registry was asked to confirm this identity",
        )
        if self._resolver is None:
            return base
        started = time.monotonic()
        try:
            async with self._resolve_slots:
                return await run_within(
                    self._deadline,
                    lambda: self._resolver.resolve_identity(  # type: ignore[union-attr]
                        image.name, image.tag, digest, self._platform
                    ),
                )
        except DeadlineExceededError:
            return replace(base, limitation="the time budget ended before the tag was resolved")
        except Exception as e:
            logger.warning(f"Could not resolve {image.name}:{image.tag}: {e}")
            return replace(base, limitation=f"identity resolution failed: {e}")
        finally:
            if self._instrumentation is not None:
                self._instrumentation.add("identity_resolution", time.monotonic() - started)
                self._instrumentation.request("registry")

    def _apply_identity(self, image: DockerImage, identity: ResolvedIdentity, digest: str) -> None:
        image.platform = str(identity.platform)
        image.index_digest = identity.index_digest
        image.identity_status = identity.status.value
        image.identity_limitation = identity.limitation
        image.requested_reference = image.requested_reference or image.full_reference
        if identity.confirmed:
            # From here on `digest` is *the platform manifest*, which is what
            # was measured. It replaces whatever the discovery source hinted.
            image.digest = identity.manifest_digest
        elif digest and not image.digest:
            image.digest = digest

    # ---- measuring ---------------------------------------------------------

    def _measured_reference(
        self, image: DockerImage, identity: ResolvedIdentity, digest: str
    ) -> str:
        if identity.confirmed:
            return identity.resolved_reference
        if digest:
            return f"{image.name}@{digest}"
        return image.full_reference

    def _run_key(self, identity: ResolvedIdentity, measured: str) -> tuple[str, ...]:
        strict = identity.identity
        if strict is not None:
            return ("confirmed", strict.cache_material)
        return ("unconfirmed", measured, str(identity.platform))

    async def measure(self, image: DockerImage) -> Measurement:
        """Measure one image. Concurrent calls for the same identity share
        one scan; the result is remembered for the rest of the run."""
        identity = await self.resolve(image)
        digest = _user_pinned_digest(image)
        measured = self._measured_reference(image, identity, digest)
        image.measured_reference = measured
        refs = identity.refs(image.requested_reference or image.full_reference, measured)

        if identity.status is IdentityStatus.PLATFORM_MISMATCH:
            return self._failed(
                image, identity, refs, ScanErrorKind.PLATFORM_UNAVAILABLE, identity.limitation
            )

        key = self._run_key(identity, measured)
        done = self._finished.get(key)
        if done is not None:
            self.stats.duplicates_avoided += 1
            return replace(done, shared=True, refs=refs)

        async def once() -> Measurement:
            return await self._measure_once(image, identity, refs, measured)

        result, joined = await self._scan_flight.run(key, once)
        if joined:
            self.stats.duplicates_avoided += 1
            result = replace(result, shared=True, refs=refs)
        self._finished[key] = result
        return result

    async def _measure_once(
        self, image: DockerImage, identity: ResolvedIdentity, refs: ImageRefs, measured: str
    ) -> Measurement:
        fingerprint = await self.fingerprint()
        strict = identity.identity
        note = ""

        if strict is not None:
            started = time.monotonic()
            lookup = await self._store.get_scan(strict, fingerprint)
            if self._instrumentation is not None:
                self._instrumentation.add("cache", time.monotonic() - started)
            if lookup.hit:
                record = lookup.value
                self.stats.cache_hits += 1
                return Measurement(
                    scan=record.scan,
                    identity=identity,
                    refs=refs,
                    provenance=self._provenance(
                        image, identity, refs, fingerprint, "cache", record.measured_at
                    ),
                    from_cache=True,
                )
            if lookup.reason not in (MissReason.ABSENT, MissReason.BYPASSED):
                note = f"{lookup.reason.value if lookup.reason else ''} {lookup.detail}".strip()

        scan = await self._scan_bounded(measured, identity)

        origin = "scan"
        if strict is not None and scan.is_verified:
            await self._store.put_scan(
                identity, fingerprint, scan, requested_reference=refs.requested, origin=origin
            )
        provenance = self._provenance(
            image, identity, refs, fingerprint, origin, scan.scan_timestamp, note=note
        )
        return Measurement(scan=scan, identity=identity, refs=refs, provenance=provenance)

    async def _scan_bounded(self, reference: str, identity: ResolvedIdentity) -> ScanResult:
        """One scanner call, behind the concurrency cap and the deadline."""
        platform = str(identity.platform)
        if (
            not identity.confirmed
            and platform != str(DEFAULT_PLATFORM)
            and not self._accepts_platform
        ):
            return self._error_scan(
                reference,
                ScanErrorKind.PLATFORM_UNAVAILABLE,
                f"this scanner cannot be told to measure {platform}; refusing to measure the "
                "host platform and file it under another",
            )
        queued = time.monotonic()
        async with self._scan_slots:
            waited = time.monotonic() - queued
            self.stats.queue_wait_seconds += waited
            if self._instrumentation is not None:
                self._instrumentation.add("queue_wait", waited)
            if not self._deadline.allows(self._min_scan_seconds):
                self.stats.not_started_deadline += 1
                return self._error_scan(
                    reference,
                    ScanErrorKind.DEADLINE_EXCEEDED,
                    "not started: the remaining time budget is too short to complete a scan",
                )
            started = time.monotonic()
            try:
                scan = await run_within(
                    self._deadline, lambda: self._call_scanner(reference, platform)
                )
            except DeadlineExceededError:
                return self._error_scan(
                    reference,
                    ScanErrorKind.DEADLINE_EXCEEDED,
                    "the time budget ended while this scan was running; it was cancelled",
                    status=ScanStatus.TIMEOUT,
                )
            finally:
                if self._instrumentation is not None:
                    self._instrumentation.add(self._stage, time.monotonic() - started)
        self.stats.scans_performed += 1
        return scan

    async def _call_scanner(self, reference: str, platform: str) -> ScanResult:
        if self._accepts_platform:
            return await self._scanner.scan(reference, platform=platform)
        return await self._scanner.scan(reference)

    # ---- batch -------------------------------------------------------------

    async def measure_many(
        self,
        images: Sequence[DockerImage],
        on_result: Callable[[DockerImage, Measurement], Awaitable[None] | None] | None = None,
    ) -> list[Measurement]:
        """Measure `images`, results in input order, one failure never spoiling
        the others. Identities are resolved concurrently, scans are bounded."""

        async def one(image: DockerImage) -> Measurement:
            try:
                result = await self.measure(image)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning(f"Failed to measure {image.full_reference}: {e}")
                result = self._failed(
                    image,
                    ResolvedIdentity(
                        name=image.name,
                        tag=image.tag,
                        platform=self._platform,
                        status=IdentityStatus.UNRESOLVED,
                    ),
                    ImageRefs(requested=image.full_reference),
                    ScanErrorKind.UNKNOWN,
                    str(e),
                    status=ScanStatus.ERROR,
                )
            if on_result is not None:
                outcome = on_result(image, result)
                if inspect.isawaitable(outcome):
                    await outcome
            return result

        return list(await asyncio.gather(*(one(image) for image in images)))

    # ---- results -----------------------------------------------------------

    def _provenance(
        self,
        image: DockerImage,
        identity: ResolvedIdentity,
        refs: ImageRefs,
        fingerprint: ScannerFingerprint,
        origin: str,
        measured_at: str,
        *,
        note: str = "",
    ) -> MeasurementProvenance:
        return MeasurementProvenance(
            origin=origin,
            measured_at=measured_at or datetime.now(tz=UTC).isoformat(),
            scanner=fingerprint.name,
            scanner_version=fingerprint.version,
            db_revision=fingerprint.db_revision,
            requested_reference=refs.requested,
            resolved_reference=refs.resolved,
            measured_reference=refs.measured,
            platform=str(identity.platform),
            index_digest=identity.index_digest,
            manifest_digest=identity.manifest_digest,
            identity_status=identity.status.value,
            limitation=identity.limitation
            or ("" if identity.confirmed else "identity not confirmed"),
            cache_note=note,
        )

    def _error_scan(
        self,
        reference: str,
        kind: ScanErrorKind,
        message: str,
        *,
        status: ScanStatus = ScanStatus.ERROR,
    ) -> ScanResult:
        return ScanResult(
            image_reference=reference,
            scanner=scanner_kind(self._scanner),
            scan_timestamp=datetime.now(tz=UTC).isoformat(),
            status=status,
            error_message=message,
            error_kind=kind,
            platform=str(self._platform),
        )

    def _failed(
        self,
        image: DockerImage,
        identity: ResolvedIdentity,
        refs: ImageRefs,
        kind: ScanErrorKind,
        message: str,
        *,
        status: ScanStatus = ScanStatus.ERROR,
    ) -> Measurement:
        scan = self._error_scan(refs.measured or image.full_reference, kind, message, status=status)
        fingerprint = self._fingerprint or ScannerFingerprint(name=scanner_kind(self._scanner))
        return Measurement(
            scan=scan,
            identity=identity,
            refs=refs,
            provenance=self._provenance(image, identity, refs, fingerprint, "scan", ""),
        )


async def _text(scanner: object, attribute: str) -> str:
    """`scanner.<attribute>()` as text, or "" when absent, failing or not text."""
    method: Any = getattr(scanner, attribute, None)
    if not callable(method):
        return ""
    try:
        value = method()
        if inspect.isawaitable(value):
            value = await value
    except Exception as e:
        logger.debug(f"Could not read {attribute} from {type(scanner).__name__}: {e}")
        return ""
    return value if isinstance(value, str) else ""
