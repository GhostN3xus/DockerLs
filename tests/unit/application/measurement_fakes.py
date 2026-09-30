"""Fakes shared by the measurement tests: a scanner, a registry resolver and a
cache, each able to misbehave in the specific ways the tests need."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from dockerls.domain.entities.scan_result import ScanErrorKind, ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.interfaces.cache_store import CacheStoreInterface
from dockerls.domain.interfaces.scanner import ScannerInterface
from dockerls.domain.value_objects.measured_identity import IdentityStatus, ResolvedIdentity
from dockerls.domain.value_objects.platform import DEFAULT_PLATFORM, Platform


def digest_of(seed: str) -> str:
    return "sha256:" + (seed * 64)[:64]


class InMemoryCache(CacheStoreInterface):
    def __init__(self) -> None:
        self.rows: dict[str, Any] = {}
        self.fail_writes = False
        self.fail_reads = False
        self.deleted: list[str] = []

    async def get(self, key: str) -> Any | None:
        if self.fail_reads:
            raise OSError("database is locked")
        return self.rows.get(key)

    async def set(self, key: str, value: Any, ttl_seconds: int = 86400) -> None:
        if self.fail_writes:
            raise OSError("database is locked")
        self.rows[key] = value

    async def delete(self, key: str) -> None:
        self.deleted.append(key)
        self.rows.pop(key, None)

    async def clear(self) -> None:
        self.rows.clear()


class FakeRegistryResolver:
    """`tags[(name, tag)]` -> (index digest, {platform: manifest digest})."""

    def __init__(self) -> None:
        self.tags: dict[tuple[str, str], tuple[str, dict[str, str]]] = {}
        self.calls: list[tuple[str, str, str, str]] = []
        self.unreachable = False
        # Resolved once, like the real inspector: the first answer stays.
        self._memo: dict[tuple[str, str, str, str], ResolvedIdentity] = {}

    def publish(self, name: str, tag: str, index: str, **manifests: str) -> None:
        self.tags[(name, tag)] = (index, {k.replace("_", "/"): v for k, v in manifests.items()})

    async def resolve_identity(
        self, name: str, tag: str, digest: str = "", platform: Platform | None = None
    ) -> ResolvedIdentity:
        wanted = platform or DEFAULT_PLATFORM
        key = (name, tag, digest, str(wanted))
        self.calls.append(key)
        if key in self._memo:
            return self._memo[key]
        await asyncio.sleep(0)
        if self.unreachable or (name, tag) not in self.tags:
            status = IdentityStatus.DIGEST_ONLY if digest else IdentityStatus.UNRESOLVED
            identity = ResolvedIdentity(
                name=name, tag=tag, platform=wanted, status=status, limitation="registry offline"
            )
        else:
            index, manifests = self.tags[(name, tag)]
            manifest = manifests.get(str(wanted))
            if manifest is None:
                identity = ResolvedIdentity(
                    name=name,
                    tag=tag,
                    platform=wanted,
                    status=IdentityStatus.PLATFORM_MISMATCH,
                    index_digest=index,
                    limitation=f"the index has no manifest for {wanted}",
                )
            else:
                identity = ResolvedIdentity(
                    name=name,
                    tag=tag,
                    platform=wanted,
                    status=IdentityStatus.CONFIRMED,
                    index_digest=index,
                    manifest_digest=manifest,
                )
        self._memo[key] = identity
        return identity


class FakeScanner(ScannerInterface):
    """Measures what the *reference* names, at the moment it is called.

    A tag reference is looked up in `live_tags` at scan time -- the way a real
    scanner pulls -- which is what lets a test move a tag between resolution
    and scan. A digest reference measures exactly that digest.
    """

    def __init__(
        self,
        *,
        version: str = "trivy 0.60.0",
        db_revision: str = "2026-09-01T00:00:00+00:00",
        options: str = "opts-v1",
        latency: float = 0.0,
    ) -> None:
        self._version = version
        self._db_revision = db_revision
        self._options = options
        self.latency = latency
        self.calls: list[tuple[str, str | None]] = []
        self.findings: dict[str, int] = {}  # digest -> number of CRITICAL findings
        self.cve_offsets: dict[str, int] = {}  # digest -> first CVE number (default 0)
        self.live_tags: dict[str, str] = {}  # "name:tag" -> digest it points at *now*
        self.on_scan: Any = None
        self.raise_for: set[str] = set()
        self.status_for: dict[str, ScanStatus] = {}
        self.in_flight = 0
        self.max_in_flight = 0
        self.refreshes = 0

    async def is_available(self) -> bool:
        return True

    async def version(self) -> str:
        return self._version

    async def db_revision(self) -> str:
        return self._db_revision

    def options(self) -> str:
        return self._options

    async def refresh_db(self) -> bool:
        self.refreshes += 1
        await asyncio.sleep(0)
        return True

    async def scan(self, image_reference: str, platform: str | None = None) -> ScanResult:
        self.calls.append((image_reference, platform))
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.on_scan is not None:
                self.on_scan(image_reference)
            if self.latency:
                await asyncio.sleep(self.latency)
            if image_reference in self.raise_for:
                raise RuntimeError(f"scanner crashed on {image_reference}")
            digest = (
                image_reference.split("@", 1)[1]
                if "@" in image_reference
                else self.live_tags.get(image_reference, "")
            )
            status = self.status_for.get(image_reference, ScanStatus.OK)
            vulns = [
                Vulnerability(
                    cve_id=f"CVE-2026-{self.cve_offsets.get(digest, 0) + i:04d}",
                    severity=Severity.CRITICAL,
                    package_name="openssl",
                    installed_version="3.0.0",
                )
                for i in range(self.findings.get(digest, 0))
            ]
            return ScanResult(
                image_reference=image_reference,
                scanner="trivy",
                vulnerabilities=vulns,
                scan_timestamp=datetime.now(tz=UTC).isoformat(),
                status=status,
                error_message="" if status is ScanStatus.OK else "boom",
                error_kind=ScanErrorKind.NONE if status is ScanStatus.OK else ScanErrorKind.UNKNOWN,
                platform=platform or "",
                os_family=digest[7:14],  # lets a test see *which* bytes were measured
            )
        finally:
            self.in_flight -= 1
