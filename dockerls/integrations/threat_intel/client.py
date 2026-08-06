from __future__ import annotations

import httpx
from loguru import logger


class ThreatIntelClient:
    """Best-effort CISA KEV + FIRST EPSS lookups. Both sources are treated
    as optional enrichment: any network/parse failure degrades to "no
    signal" (empty set / 0.0 score) instead of breaking the scan."""

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, timeout: int = 15):
        self._timeout = timeout
        self._kev_ids: set[str] | None = None

    async def _load_kev(self) -> set[str]:
        if self._kev_ids is not None:
            return self._kev_ids
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(self.KEV_URL)
                resp.raise_for_status()
                data = resp.json()
                self._kev_ids = {
                    str(v.get("cveID", "")).upper() for v in data.get("vulnerabilities", [])
                }
        except (httpx.HTTPError, ValueError) as e:
            logger.debug(f"CISA KEV catalog unavailable, continuing without it: {e}")
            self._kev_ids = set()
        return self._kev_ids

    async def known_exploited(self, cve_ids: list[str]) -> set[str]:
        """Return the subset of `cve_ids` present in the CISA KEV catalog."""
        if not cve_ids:
            return set()
        kev = await self._load_kev()
        return {cve.upper() for cve in cve_ids if cve.upper() in kev}

    async def epss_scores(self, cve_ids: list[str]) -> dict[str, float]:
        """Return {cve_id: epss_probability} for whatever FIRST.org returns;
        missing/unreachable CVEs are simply absent from the result."""
        if not cve_ids:
            return {}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(self.EPSS_URL, params={"cve": ",".join(cve_ids)})
                resp.raise_for_status()
                data = resp.json()
                return {
                    entry["cve"].upper(): float(entry["epss"])
                    for entry in data.get("data", [])
                    if "cve" in entry and "epss" in entry
                }
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as e:
            logger.debug(f"EPSS lookup unavailable, continuing without it: {e}")
            return {}
