from __future__ import annotations

import httpx
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential


class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, timeout: int = 30):
        self._timeout = timeout

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, max=30))
    async def get_cve_details(self, cve_id: str) -> dict | None:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                resp = await client.get(self.BASE_URL, params={"cveId": cve_id})
                if resp.status_code == 200:
                    data = resp.json()
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        return vulns[0].get("cve", {})
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
        for ref in details.get("references", []):
            if set(ref.get("tags", [])) & exploit_tags:
                return True
        return False
