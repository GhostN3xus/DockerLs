from __future__ import annotations

from datetime import datetime, timezone

import httpx
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential

from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface


class EndOfLifeChecker(EOLCheckerInterface):
    BASE_URL = "https://endoflife.date/api"

    def __init__(self, timeout: int = 15):
        self._timeout = timeout
        self._cache: dict[str, list[dict]] = {}

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
    async def _fetch_product(self, product: str) -> list[dict]:
        if product in self._cache:
            return self._cache[product]
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                resp = await client.get(f"{self.BASE_URL}/{product}.json")
                if resp.status_code == 200:
                    data = resp.json()
                    self._cache[product] = data
                    return data
                return []
            except httpx.HTTPError as e:
                logger.debug(f"EOL check failed for {product}: {e}")
                return []

    async def is_eol(self, product: str, version: str) -> bool:
        if not version:
            return False
        cycles = await self._fetch_product(product)
        for cycle in cycles:
            cycle_ver = str(cycle.get("cycle", ""))
            if cycle_ver == version or version.startswith(cycle_ver):
                eol = cycle.get("eol")
                if isinstance(eol, bool):
                    return eol
                if isinstance(eol, str):
                    try:
                        eol_date = datetime.strptime(eol, "%Y-%m-%d").replace(
                            tzinfo=timezone.utc
                        )
                        return datetime.now(tz=timezone.utc) > eol_date
                    except ValueError:
                        pass
        return False

    async def is_lts(self, product: str, version: str) -> bool:
        if not version:
            return False
        cycles = await self._fetch_product(product)
        for cycle in cycles:
            cycle_ver = str(cycle.get("cycle", ""))
            if cycle_ver == version or version.startswith(cycle_ver):
                return bool(cycle.get("lts", False))
        return False
