"""OSV.dev advisory data, matched strictly by CVE-ID.

This is supplementary enrichment, not a second vulnerability database: Trivy
and Grype already found the CVE and its severity, and this client's only job
is to attach what they do not carry -- the advisory's other identifiers
(`aliases`, e.g. a GHSA ID for a CVE that started life on GitHub) and a
human-readable summary of the affected version ranges OSV publishes for it.
Nothing here re-scores or re-classifies a finding.

Same shape as `ThreatIntelClient`'s EPSS lookups: a per-CVE disk cache,
`retry_policy` + `RateLimiter` + `CircuitBreaker` for the HTTP call, and an
`available` tri-state so a caller can tell "OSV was consulted and has
nothing more to say about this CVE" from "OSV could not be reached" --
failure must never read as "no aliases, no ranges" being a fact about the
CVE rather than an absence of a lookup.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import httpx
from loguru import logger

from dockerls.integrations.threat_intel.status import IntelStatus
from dockerls.utils.rate_limit import CircuitBreaker, CircuitOpenError, RateLimiter
from dockerls.utils.retry import (
    DEFAULT_BACKOFF_BASE,
    DEFAULT_MAX_ATTEMPTS,
    retry_policy,
)
from dockerls.utils.single_flight import SingleFlight

if TYPE_CHECKING:
    from dockerls.domain.interfaces.cache_store import CacheStoreInterface

#: A public, unauthenticated API with no documented per-client budget.
#: Conservative default that paces a burst of concurrent lookups within one
#: run, not a number derived from OSV's own docs.
_RATE = 10
_RATE_PERIOD = 1.0


class OSVEnrichment:
    """Advisory metadata for one CVE, reduced to what a report can show."""

    __slots__ = ("aliases", "affected_ranges")

    def __init__(self, aliases: list[str], affected_ranges: list[str]):
        self.aliases = aliases
        self.affected_ranges = affected_ranges

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"OSVEnrichment(aliases={self.aliases!r}, affected_ranges={self.affected_ranges!r})"


def _parse_osv_record(data: Any) -> OSVEnrichment:
    """Reduce one OSV vulnerability record to aliases + affected ranges.

    Every access here is defensive: the record is untrusted third-party
    JSON, and a shape this does not expect yields an empty (never a
    fabricated) result rather than raising.
    """
    if not isinstance(data, dict):
        return OSVEnrichment(aliases=[], affected_ranges=[])

    aliases = [a for a in data.get("aliases", []) if isinstance(a, str)]

    ranges: list[str] = []
    affected = data.get("affected")
    if isinstance(affected, list):
        for entry in affected:
            if not isinstance(entry, dict):
                continue
            package = entry.get("package")
            pkg_name = package.get("name") if isinstance(package, dict) else None
            entry_ranges = entry.get("ranges")
            if not isinstance(entry_ranges, list):
                continue
            for one_range in entry_ranges:
                if not isinstance(one_range, dict):
                    continue
                events = one_range.get("events")
                if not isinstance(events, list):
                    continue
                parts = [
                    f"{key}={event[key]}"
                    for event in events
                    if isinstance(event, dict)
                    for key in ("introduced", "fixed", "last_affected", "limit")
                    if key in event
                ]
                if not parts:
                    continue
                label = f"{pkg_name}: " if isinstance(pkg_name, str) and pkg_name else ""
                ranges.append(label + ", ".join(parts))

    return OSVEnrichment(aliases=aliases, affected_ranges=ranges)


class OSVClient:
    """Best-effort OSV.dev lookups by CVE-ID. Complements, never replaces,
    what the scanners already reported for a finding.

    OSV has no batch endpoint keyed by vulnerability ID (`/v1/querybatch`
    answers package/version queries), so each distinct CVE is one GET. What is
    shared instead is everything around it: one HTTP client and its
    connections for the whole run, one in-flight request per CVE however many
    candidates ask, a bound on simultaneous requests, and both kinds of answer
    remembered -- a record, and a confirmed 404 (for a shorter time).
    """

    BASE_URL = "https://api.osv.dev/v1"

    # Advisories move far slower than the daily KEV/EPSS feeds; a day's TTL
    # avoids re-fetching the same CVE across back-to-back runs.
    CACHE_TTL_SECONDS = 24 * 60 * 60
    #: A confirmed "OSV has no such record". Shorter than a positive answer:
    #: an advisory can be published any day, and an absence is only as good as
    #: the moment it was checked.
    ABSENT_TTL_SECONDS = 6 * 60 * 60
    _CACHE_PREFIX = "threat-intel:osv:v1:"
    _ABSENT_PREFIX = "threat-intel:osv-absent:v1:"
    #: Simultaneous GETs. Independent of the rate limiter, which paces the
    #: *start* of requests; this bounds how many are open at once.
    MAX_CONCURRENT = 8

    def __init__(
        self,
        timeout: int = 15,
        cache: CacheStoreInterface | None = None,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_base: float = DEFAULT_BACKOFF_BASE,
    ):
        self._timeout = timeout
        self._cache = cache
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base
        # None before anything was asked, True once OSV answered at least
        # one lookup (found or not-found are both real answers), False
        # after every attempt in a run failed.
        self._available: bool | None = None
        self._limiter = RateLimiter(rate=_RATE, period=_RATE_PERIOD)
        self._breaker = CircuitBreaker()
        self._http: httpx.AsyncClient | None = None
        self._http_lock = asyncio.Lock()
        self._slots = asyncio.Semaphore(self.MAX_CONCURRENT)
        self._flight: SingleFlight[tuple[IntelStatus, OSVEnrichment | None]] = SingleFlight()
        self._status: dict[str, IntelStatus] = {}
        #: Requests actually sent, cache answers and joined lookups, for the
        #: run's instrumentation.
        self.requests = 0
        self.cache_hits = 0
        self.joined = 0

    @property
    def available(self) -> bool | None:
        """True once OSV answered at least one lookup, False after every
        lookup in this run failed, None before anything was asked."""
        return self._available

    def status_of(self, cve_id: str) -> IntelStatus | None:
        """What the lookup of `cve_id` established this run, or None if it was
        never asked. Distinguishes a confirmed absence from every way of not
        having an answer."""
        return self._status.get(cve_id.upper())

    async def close(self) -> None:
        """Release the shared connection pool."""
        client, self._http = self._http, None
        if client is not None:
            await client.aclose()

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            async with self._http_lock:
                if self._http is None:
                    self._http = httpx.AsyncClient(timeout=self._timeout)
        return self._http

    async def enrich(self, cve_ids: list[str]) -> dict[str, OSVEnrichment]:
        """Map each of `cve_ids` that OSV has a record for to its aliases
        and affected ranges.

        A CVE absent from the result was either confirmed absent (see
        `status_of`, `ABSENT`) or could not be looked up this run
        (`NETWORK_ERROR`, `RATE_LIMITED`, ...) -- the two are told apart by
        `status_of`, never by the result alone.
        """
        if not cve_ids:
            return {}
        wanted = sorted({cve.upper() for cve in cve_ids})
        outcomes = await asyncio.gather(*(self._lookup(cve) for cve in wanted))
        result: dict[str, OSVEnrichment] = {}
        for cve, (status, enrichment) in zip(wanted, outcomes, strict=True):
            self._status[cve] = status
            if status.answered:
                self._available = True
            if enrichment is not None:
                result[cve] = enrichment
        if self._available is None:
            self._available = False
        return result

    async def _lookup(self, cve: str) -> tuple[IntelStatus, OSVEnrichment | None]:
        """One CVE, shared by every caller that asks while it is in flight."""
        outcome, joined = await self._flight.run(cve, lambda: self._resolve(cve))
        if joined:
            self.joined += 1
        return outcome

    async def _resolve(self, cve: str) -> tuple[IntelStatus, OSVEnrichment | None]:
        cached = await self._from_cache(cve)
        if cached is not None:
            self.cache_hits += 1
            return cached
        async with self._slots:
            status, enrichment = await self._fetch_one(cve)
        if status is IntelStatus.FOUND and enrichment is not None:
            await self._store_cache(cve, enrichment)
        elif status is IntelStatus.ABSENT:
            await self._store_absent(cve)
        return status, enrichment

    @staticmethod
    async def _get_raising_5xx(client: httpx.AsyncClient, url: str) -> httpx.Response:
        """GET, raising on a 5xx or a 429 so the retry policy sees a transient
        failure. Any other 4xx (404 "no such record", ...) is returned as-is
        for the caller to interpret -- retrying a 404 would never turn it into
        an answer."""
        resp = await client.get(url)
        if resp.status_code >= 500 or resp.status_code == 429:
            resp.raise_for_status()
        return resp

    async def _fetch_one(self, cve: str) -> tuple[IntelStatus, OSVEnrichment | None]:
        """One network lookup, classified: never "found nothing" for a failure."""
        try:
            self._breaker.check("OSV.dev")
        except CircuitOpenError as e:
            logger.debug(str(e))
            return IntelStatus.UNAVAILABLE, None
        try:
            client = await self._client()
            await self._limiter.acquire()
            policy = retry_policy(self._max_attempts, self._backoff_base)
            self.requests += 1
            resp: httpx.Response = await policy(
                self._get_raising_5xx, client, f"{self.BASE_URL}/vulns/{cve}"
            )
        except httpx.HTTPStatusError as e:
            self._breaker.record_failure()
            limited = e.response.status_code == 429
            logger.debug(f"OSV.dev lookup failed for {cve}: HTTP {e.response.status_code}")
            return (IntelStatus.RATE_LIMITED if limited else IntelStatus.NETWORK_ERROR), None
        except httpx.HTTPError as e:
            self._breaker.record_failure()
            logger.debug(f"OSV.dev lookup failed for {cve}: {e}")
            return IntelStatus.NETWORK_ERROR, None

        if resp.status_code == 404:
            self._breaker.record_success()
            return IntelStatus.ABSENT, None
        if not resp.is_success:
            self._breaker.record_failure()
            logger.debug(f"OSV.dev answered {resp.status_code} for {cve}")
            return IntelStatus.INVALID_RESPONSE, None
        try:
            data = resp.json()
        except ValueError as e:
            self._breaker.record_failure()
            logger.debug(f"OSV.dev response for {cve} was not valid JSON: {e}")
            return IntelStatus.INVALID_RESPONSE, None
        if not isinstance(data, dict):
            self._breaker.record_failure()
            return IntelStatus.INVALID_RESPONSE, None
        self._breaker.record_success()
        return IntelStatus.FOUND, _parse_osv_record(data)

    async def _from_cache(self, cve: str) -> tuple[IntelStatus, OSVEnrichment | None] | None:
        if self._cache is None:
            return None
        try:
            data = await self._cache.get(self._CACHE_PREFIX + cve)
            if data is None:
                absent = await self._cache.get(self._ABSENT_PREFIX + cve)
                if isinstance(absent, dict) and absent.get("absent") is True:
                    return IntelStatus.ABSENT, None
                return None
        except Exception as e:  # pragma: no cover - an unreadable cache is a miss
            logger.debug(f"Could not read the cached OSV record for {cve}: {e}")
            return None
        if not isinstance(data, dict):
            return None
        aliases = data.get("aliases")
        ranges = data.get("affected_ranges")
        if not isinstance(aliases, list) or not isinstance(ranges, list):
            return None
        return IntelStatus.FOUND, OSVEnrichment(
            aliases=[str(a) for a in aliases], affected_ranges=[str(r) for r in ranges]
        )

    async def _store_cache(self, cve: str, enrichment: OSVEnrichment) -> None:
        if self._cache is None:
            return
        payload = {"aliases": enrichment.aliases, "affected_ranges": enrichment.affected_ranges}
        try:
            await self._cache.set(
                self._CACHE_PREFIX + cve, payload, ttl_seconds=self.CACHE_TTL_SECONDS
            )
        except Exception as e:  # pragma: no cover - a cache that will not write is not fatal
            logger.debug(f"Could not cache the OSV record for {cve}: {e}")

    async def _store_absent(self, cve: str) -> None:
        """Remember a *confirmed* 404, briefly. Never called for a failure."""
        if self._cache is None:
            return
        try:
            await self._cache.set(
                self._ABSENT_PREFIX + cve, {"absent": True}, ttl_seconds=self.ABSENT_TTL_SECONDS
            )
        except Exception as e:  # pragma: no cover - a cache that will not write is not fatal
            logger.debug(f"Could not cache the OSV absence for {cve}: {e}")
