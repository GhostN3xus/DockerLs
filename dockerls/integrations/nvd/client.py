from __future__ import annotations

import asyncio
import time
from typing import Any, cast

import httpx
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential


class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Per NVD API docs: 5 requests/30s without a key, 50 requests/30s with one.
    _WINDOW_SECONDS = 30.0
    _REQUESTS_PER_WINDOW_NO_KEY = 5
    _REQUESTS_PER_WINDOW_WITH_KEY = 50

    def __init__(self, timeout: int = 30, api_key: str = ""):
        self._timeout = timeout
        self._api_key = api_key
        self._min_interval = self._WINDOW_SECONDS / (
            self._REQUESTS_PER_WINDOW_WITH_KEY if api_key else self._REQUESTS_PER_WINDOW_NO_KEY
        )
        self._last_request_at = 0.0
        self._rate_lock = asyncio.Lock()

    async def _throttle(self) -> None:
        async with self._rate_lock:
            elapsed = time.monotonic() - self._last_request_at
            wait = self._min_interval - elapsed
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_at = time.monotonic()

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, max=30))
    async def get_cve_details(self, cve_id: str) -> dict[str, Any] | None:
        await self._throttle()
        headers = {"apiKey": self._api_key} if self._api_key else {}
        async with httpx.AsyncClient(timeout=self._timeout, headers=headers) as client:
            try:
                resp = await client.get(self.BASE_URL, params={"cveId": cve_id})
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        return cast("dict[str, Any]", vulns[0].get("cve", {}))
                elif resp.status_code == 403:
                    logger.warning("NVD rate limit reached")
                return None
            except httpx.HTTPError as e:
                logger.warning(f"NVD lookup failed for {cve_id}: {e}")
                return None

    async def has_known_exploit(self, cve_id: str) -> bool:
        details = await self.get_cve_details(cve_id)
        if not details:
            return False
        exploit_tags = {"Exploit", "Third Party Advisory"}
        return any(set(ref.get("tags", [])) & exploit_tags for ref in details.get("references", []))
