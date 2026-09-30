from __future__ import annotations

import asyncio
import math
from typing import TYPE_CHECKING, Literal

import httpx
from loguru import logger

from dockerls.integrations.threat_intel.status import IntelStatus
from dockerls.utils.rate_limit import CircuitBreaker, CircuitOpenError, RateLimiter
from dockerls.utils.retry import (
    DEFAULT_BACKOFF_BASE,
    DEFAULT_MAX_ATTEMPTS,
    retry_policy,
)

if TYPE_CHECKING:
    from dockerls.domain.interfaces.cache_store import CacheStoreInterface

#: Smallest catalogue that could plausibly be the real KEV feed. It has
#: carried more than a thousand entries since 2023 and only grows, so a
#: floor an order of magnitude below that discriminates against proxy error
#: pages and truncated transfers, not against the feed.
MIN_PLAUSIBLE_KEV_ENTRIES = 100

#: Both feeds are public, unauthenticated APIs with no documented per-client
#: budget. These are conservative defaults that pace a burst of concurrent
#: lookups within one run, not numbers derived from either provider's docs.
_KEV_RATE = 5
_EPSS_RATE = 10
_RATE_PERIOD = 1.0


def _probability(value: object) -> float | None:
    """A finite 0.0-1.0 float, or None when the value is not one."""
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or not (0.0 <= number <= 1.0):
        return None
    return number


class ThreatIntelClient:
    """Best-effort CISA KEV + FIRST EPSS lookups. Both sources are treated
    as optional enrichment: any network/parse failure degrades to "no
    signal" (empty set / 0.0 score) instead of breaking the scan."""

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_URL = "https://api.first.org/data/v1/epss"

    # Both feeds move roughly daily -- KEV gets a handful of new entries a
    # day, EPSS republishes once a day -- so a fresher copy buys nothing and
    # costs a full re-download (KEV) or one HTTP round trip per CVE (EPSS)
    # on every single invocation. Without this, `recommend` re-fetched the
    # whole KEV catalogue and re-queried EPSS for every CRITICAL/HIGH CVE on
    # every run, even back-to-back runs against the same image.
    CACHE_TTL_SECONDS = 24 * 60 * 60
    _KEV_CACHE_KEY = "threat-intel:kev:v1"
    _EPSS_CACHE_PREFIX = "threat-intel:epss:v1:"
    #: FIRST answered and has no score for this CVE. Remembered for an hour
    #: only: new CVEs are scored within a day, so a longer memory would
    #: keep reporting "not scored" for something FIRST has since scored.
    _EPSS_ABSENT_PREFIX = "threat-intel:epss-absent:v1:"
    EPSS_ABSENT_TTL_SECONDS = 3600

    def __init__(
        self,
        timeout: int = 15,
        cache: CacheStoreInterface | None = None,
        min_kev_entries: int = MIN_PLAUSIBLE_KEV_ENTRIES,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_base: float = DEFAULT_BACKOFF_BASE,
    ):
        self._timeout = timeout
        self._cache = cache
        # Injectable so a test can exercise the parsing path with a small
        # fixture without lowering the floor that protects real runs.
        self._min_kev_entries = min_kev_entries
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base
        # One limiter/breaker per feed: KEV and EPSS are different hosts
        # with different call shapes (one download vs many small batches),
        # so a run of failures against one must not throttle the other.
        self._kev_limiter = RateLimiter(rate=_KEV_RATE, period=_RATE_PERIOD)
        self._kev_breaker = CircuitBreaker()
        self._epss_limiter = RateLimiter(rate=_EPSS_RATE, period=_RATE_PERIOD)
        self._epss_breaker = CircuitBreaker()
        self._kev_ids: set[str] | None = None
        # Whether each feed actually answered during this run. Without this,
        # "no KEV hits" and "the KEV catalogue was unreachable" are the same
        # empty set, and the caller cannot tell a negative finding from a
        # missing lookup.
        self._kev_available: bool | None = None
        self._epss_available: bool | None = None
        # EPSS percentiles, kept alongside the probabilities. A probability
        # of 0.42 means little on its own; the percentile says where that
        # sits among everything FIRST scored, which is what makes it
        # comparable between runs on different days.
        self._percentiles: dict[str, float] = {}
        # `recommend` enriches every tag concurrently, and the memo below is
        # only populated *after* the first download finishes. Without this
        # lock, a 100-tag run started 100 simultaneous downloads of the same
        # multi-megabyte KEV catalogue -- a self-inflicted burst against
        # cisa.gov that the memo was written to prevent.
        self._kev_lock = asyncio.Lock()
        # One client, and so one connection pool, for the whole run: KEV and
        # every EPSS batch used to open (and tear down) their own.
        self._http: httpx.AsyncClient | None = None
        self._http_lock = asyncio.Lock()
        # CVE -> a future for its EPSS lookup while one is in flight. Several
        # candidates share most of their CRITICAL/HIGH CVEs, and enriching them
        # concurrently used to send the same CVE to FIRST.org once per
        # candidate; now the first asker fetches it and the rest wait.
        self._epss_pending: dict[str, asyncio.Future[IntelStatus]] = {}
        self._epss_status: dict[str, IntelStatus] = {}
        # Scores learned this run, so a CVE asked for again is never re-asked
        # even when there is no persistent cache behind the client.
        self._epss_scores: dict[str, float] = {}
        #: Requests sent, and lookups answered without one, for the run's
        #: instrumentation.
        self.requests: dict[str, int] = {"kev": 0, "epss": 0}
        self.cache_hits = 0
        self.joined = 0

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

    def epss_status_of(self, cve_id: str) -> IntelStatus | None:
        """What the EPSS lookup of `cve_id` established this run, or None if it
        was never asked. `ABSENT` means FIRST answered and has no score --
        which is not the same as the feed being down."""
        return self._epss_status.get(cve_id.upper())

    async def _load_kev(self) -> set[str]:
        if self._kev_ids is not None:
            return self._kev_ids
        async with self._kev_lock:
            if self._kev_ids is not None:
                return self._kev_ids
            cached = await self._kev_from_cache()
            if cached is not None:
                self._kev_available = True
                self._kev_ids = cached
                return self._kev_ids
            self._kev_ids = await self._fetch_kev()
            if self._kev_ids:
                await self._store_kev_cache(self._kev_ids)
        return self._kev_ids

    async def _kev_from_cache(self) -> set[str] | None:
        if self._cache is None:
            return None
        try:
            data = await self._cache.get(self._KEV_CACHE_KEY)
        except Exception as e:  # pragma: no cover - an unreadable cache is a miss
            logger.debug(f"Could not read the cached KEV catalogue: {e}")
            return None
        if not isinstance(data, list) or not data:
            return None
        return {str(cve).upper() for cve in data}

    async def _store_kev_cache(self, ids: set[str]) -> None:
        if self._cache is None:
            return
        try:
            await self._cache.set(
                self._KEV_CACHE_KEY, sorted(ids), ttl_seconds=self.CACHE_TTL_SECONDS
            )
        except Exception as e:  # pragma: no cover - a cache that will not write is not fatal
            logger.debug(f"Could not cache the KEV catalogue: {e}")

    @property
    def kev_available(self) -> bool | None:
        """True once the KEV catalogue answered, False after it failed,
        None before anything was asked."""
        return self._kev_available

    @property
    def epss_available(self) -> bool | None:
        """True once at least one EPSS batch answered; see `kev_available`."""
        return self._epss_available

    @staticmethod
    async def _get_raising(client: httpx.AsyncClient, url: str, **kwargs: object) -> httpx.Response:
        """GET and raise on a non-2xx status, all inside one retryable step.

        A bare `client.get(...)` never raises on a 5xx by itself, so the
        `raise_for_status()` has to live *inside* the callable the retry
        policy re-invokes -- otherwise only the network call is retried and
        a persistent 5xx would be seen (and given up on) after one attempt.
        """
        resp = await client.get(url, **kwargs)  # type: ignore[arg-type]
        resp.raise_for_status()
        return resp

    async def _fetch_kev(self) -> set[str]:
        try:
            self._kev_breaker.check("CISA KEV")
        except CircuitOpenError as e:
            logger.warning(str(e))
            self._kev_available = False
            return set()
        try:
            await self._kev_limiter.acquire()
            client = await self._client()
            policy = retry_policy(self._max_attempts, self._backoff_base)
            self.requests["kev"] += 1
            resp: httpx.Response = await policy(self._get_raising, client, self.KEV_URL)
            data = resp.json()
            if not isinstance(data, dict):
                raise ValueError(f"KEV payload was {type(data).__name__}, not an object")
            entries = data.get("vulnerabilities", [])
            if not isinstance(entries, list):
                raise ValueError(f"KEV payload 'vulnerabilities' was {type(entries).__name__}")
            ids = {
                str(v.get("cveID", "")).upper()
                for v in entries
                if isinstance(v, dict) and v.get("cveID")
            }
            # A short catalogue is not a successful lookup either. The
            # real feed carries thousands of entries, so a handful means
            # a proxy error page, a truncated transfer or a captive
            # portal parsed as JSON. Accepting it would mark every CVE
            # not in that handful as `kev_status = FALSE` -- an
            # affirmative "not known to be exploited" derived from a
            # response that was never the catalogue.
            self._kev_available = len(ids) >= self._min_kev_entries
            self._kev_breaker.record_success()
            if ids and not self._kev_available:
                logger.warning(
                    f"CISA KEV answered with only {len(ids)} entries, far below the "
                    f"{self._min_kev_entries} a real catalogue carries; treating "
                    f"exploitation status as UNKNOWN rather than trusting it"
                )
                return set()
            return ids
        except (httpx.HTTPError, ValueError) as e:
            self._kev_breaker.record_failure()
            logger.warning(
                f"CISA KEV catalog unavailable: exploitation status will be UNKNOWN ({e})"
            )
            self._kev_available = False
            return set()

    async def known_exploited(self, cve_ids: list[str]) -> set[str]:
        """Return the subset of `cve_ids` present in the CISA KEV catalog."""
        if not cve_ids:
            return set()
        kev = await self._load_kev()
        return {cve.upper() for cve in cve_ids if cve.upper() in kev}

    # A API do FIRST pagina o resultado e a query vai na URL. Pedir 200 CVEs
    # de uma vez devolvia calado só a primeira página -- e o restante perdia
    # o sinal de EPSS justamente nas imagens que mais têm CRITICAL/HIGH, que
    # são as que mais precisam dele. O lote é pedido com `limit` explícito
    # em vez de confiar no default do serviço.
    EPSS_BATCH_SIZE = 100

    async def epss_scores(self, cve_ids: list[str]) -> dict[str, float]:
        """Return {cve_id: epss_probability} for whatever FIRST.org returns;
        missing/unreachable CVEs are simply absent from the result.

        Checked against the cache first, one CVE at a time: `recommend`
        enriches dozens of tags of the same image family, and their
        CRITICAL/HIGH findings overlap heavily (the same OS package CVE
        shows up in `node:20`, `node:22` and every variant of each). Without
        this, every one of those tags re-queried FIRST.org for CVEs this
        process, or an earlier run today, had already scored.
        """
        if not cve_ids:
            return {}

        wanted = sorted({cve.upper() for cve in cve_ids})
        scores: dict[str, float] = {}
        for cve in wanted:
            if cve in self._epss_scores:
                scores[cve] = self._epss_scores[cve]
        remaining = [cve for cve in wanted if cve not in scores]
        if self._cache is not None and remaining:
            cached = await asyncio.gather(*[self._epss_from_cache(cve) for cve in remaining])
            for cve, hit in zip(remaining, cached, strict=True):
                if hit is None:
                    continue
                self.cache_hits += 1
                if hit == "absent":
                    self._epss_status[cve] = IntelStatus.ABSENT
                    continue
                scores[cve] = hit[0]
                self._epss_scores[cve] = hit[0]
                self._percentiles[cve] = hit[1]
                self._epss_status[cve] = IntelStatus.FOUND
        missing = [
            cve
            for cve in wanted
            if cve not in scores and self._epss_status.get(cve) is not IntelStatus.ABSENT
        ]
        if cached_hit := bool(scores):
            self._epss_available = True

        # Split what is left into what this call must fetch and what another
        # call is already fetching: the second group is simply awaited.
        loop = asyncio.get_running_loop()
        owned: list[str] = []
        joined: dict[str, asyncio.Future[IntelStatus]] = {}
        for cve in missing:
            pending = self._epss_pending.get(cve)
            if pending is not None:
                joined[cve] = pending
                continue
            self._epss_pending[cve] = loop.create_future()
            owned.append(cve)

        try:
            if owned:
                client = await self._client()
                for start in range(0, len(owned), self.EPSS_BATCH_SIZE):
                    batch = owned[start : start + self.EPSS_BATCH_SIZE]
                    # Um lote que falha não pode descartar os que já vieram: o
                    # sinal parcial ainda é melhor que nenhum.
                    batch_scores, failure = await self._epss_batch(client, batch)
                    # An answer proves the feed is alive only if it carried at
                    # least one usable score: an empty or unusable 200 is what
                    # a broken proxy also produces, and neither availability
                    # nor an "absent" verdict may rest on it.
                    sane = failure is None and bool(batch_scores)
                    if sane:
                        self._epss_available = True
                    scores.update(batch_scores)
                    self._epss_scores.update(batch_scores)
                    await self._store_epss_cache(batch_scores)
                    if sane:
                        await self._store_epss_absent([c for c in batch if c not in batch_scores])
                    for cve in batch:
                        if cve in batch_scores:
                            status = IntelStatus.FOUND
                        elif failure is not None:
                            status = failure
                        elif sane:
                            # The feed answered *and* was plausible, without
                            # this CVE: a finding, not a failure.
                            status = IntelStatus.ABSENT
                        else:
                            status = IntelStatus.INVALID_RESPONSE
                        self._epss_status[cve] = status
                        self._resolve_pending(cve, status)
        finally:
            for cve in owned:
                # Anything not resolved above (a cancellation, an unexpected
                # error) must still release its waiters, as a failure.
                self._resolve_pending(cve, IntelStatus.NETWORK_ERROR)

        for cve, future in joined.items():
            self.joined += 1
            await future
            if cve in self._epss_scores:
                scores[cve] = self._epss_scores[cve]
        if self._epss_available is None and not cached_hit:
            # Every batch came back empty and nothing was cached: either the
            # service is down or it knows none of these CVEs. Neither
            # supports a claim of low exploitation probability.
            self._epss_available = False
        return scores

    def _resolve_pending(self, cve: str, status: IntelStatus) -> None:
        future = self._epss_pending.pop(cve, None)
        if future is not None and not future.done():
            future.set_result(status)

    async def _epss_from_cache(self, cve: str) -> tuple[float, float] | Literal["absent"] | None:
        if self._cache is None:
            return None
        try:
            data = await self._cache.get(self._EPSS_CACHE_PREFIX + cve)
            if data is None:
                absent = await self._cache.get(self._EPSS_ABSENT_PREFIX + cve)
                return "absent" if isinstance(absent, dict) and absent.get("absent") else None
        except Exception as e:  # pragma: no cover - an unreadable cache is a miss
            logger.debug(f"Could not read the cached EPSS score for {cve}: {e}")
            return None
        if not isinstance(data, dict) or "score" not in data:
            return None
        score = _probability(data["score"])
        if score is None:
            # A row written before this check existed may still carry a
            # NaN/out-of-range value on disk; treat it the same as a miss
            # rather than serving it back as a probability.
            return None
        percentile = _probability(data.get("percentile", 0.0)) or 0.0
        return score, percentile

    async def _store_epss_cache(self, batch_scores: dict[str, float]) -> None:
        if self._cache is None or not batch_scores:
            return
        for cve, score in batch_scores.items():
            payload = {"score": score, "percentile": self._percentiles.get(cve, 0.0)}
            try:
                await self._cache.set(
                    self._EPSS_CACHE_PREFIX + cve, payload, ttl_seconds=self.CACHE_TTL_SECONDS
                )
            except Exception as e:  # pragma: no cover - a cache that will not write is not fatal
                logger.debug(f"Could not cache the EPSS score for {cve}: {e}")

    async def _store_epss_absent(self, cves: list[str]) -> None:
        """Remember CVEs a *successful* EPSS answer did not contain. Never
        called for a failed batch: an outage is not an absence."""
        if self._cache is None:
            return
        for cve in cves:
            try:
                await self._cache.set(
                    self._EPSS_ABSENT_PREFIX + cve,
                    {"absent": True},
                    ttl_seconds=self.EPSS_ABSENT_TTL_SECONDS,
                )
            except Exception as e:  # pragma: no cover - a cache that will not write is not fatal
                logger.debug(f"Could not cache the EPSS absence for {cve}: {e}")

    def percentile_of(self, cve_id: str) -> float:
        """EPSS percentile for `cve_id`, or 0.0 when the source did not
        provide one. Only meaningful when `epss_available` is True."""
        return self._percentiles.get(cve_id.upper(), 0.0)

    async def _epss_batch(
        self, client: httpx.AsyncClient, batch: list[str]
    ) -> tuple[dict[str, float], IntelStatus | None]:
        """One EPSS request: `(scores, None)` when FIRST answered, and
        `({}, why)` when it did not, so a failure is never read as "these
        CVEs have no score"."""
        try:
            self._epss_breaker.check("FIRST EPSS")
        except CircuitOpenError as e:
            logger.debug(str(e))
            return {}, IntelStatus.UNAVAILABLE
        try:
            await self._epss_limiter.acquire()
            policy = retry_policy(self._max_attempts, self._backoff_base)
            self.requests["epss"] += 1
            resp: httpx.Response = await policy(
                self._get_raising,
                client,
                self.EPSS_URL,
                params={"cve": ",".join(batch), "limit": str(len(batch))},
            )
            data = resp.json()
            scores: dict[str, float] = {}
            for entry in data.get("data", []):
                if "cve" not in entry or "epss" not in entry:
                    continue
                cve = entry["cve"].upper()
                probability = _probability(entry["epss"])
                if probability is None:
                    # `float()` accepts "nan", "inf" and "-1"; none of them
                    # is a probability, and all of them reached the scoring
                    # engine. Dropping the CVE from the result leaves it
                    # `epss_known = False` downstream, which is the honest
                    # reading: the feed answered, but not with a number.
                    logger.warning(
                        f"Discarding implausible EPSS value for {cve}: {entry['epss']!r}"
                    )
                    continue
                scores[cve] = probability
                percentile = _probability(entry.get("percentile"))
                if percentile is not None:
                    self._percentiles[cve] = percentile
            self._epss_breaker.record_success()
            return scores, None
        except httpx.HTTPStatusError as e:
            self._epss_breaker.record_failure()
            logger.debug(f"EPSS lookup failed for {len(batch)} CVEs: HTTP {e.response.status_code}")
            limited = e.response.status_code == 429
            return {}, IntelStatus.RATE_LIMITED if limited else IntelStatus.NETWORK_ERROR
        except httpx.HTTPError as e:
            self._epss_breaker.record_failure()
            logger.debug(f"EPSS lookup unavailable for {len(batch)} CVEs, continuing without: {e}")
            return {}, IntelStatus.NETWORK_ERROR
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            self._epss_breaker.record_failure()
            logger.debug(f"EPSS answered with something unusable for {len(batch)} CVEs: {e}")
            return {}, IntelStatus.INVALID_RESPONSE
