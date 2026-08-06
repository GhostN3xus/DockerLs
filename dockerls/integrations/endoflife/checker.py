from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import httpx
from loguru import logger

from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.utils.retry import (
    DEFAULT_BACKOFF_BASE,
    DEFAULT_MAX_ATTEMPTS,
    retry_policy,
)

# Docker Hub image name -> endoflife.date product slug. Docker Hub names and
# endoflife.date slugs frequently diverge (e.g. "node" vs "nodejs").
DOCKER_TO_ENDOFLIFE: dict[str, str] = {
    "node": "nodejs",
    "python": "python",
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "redis": "redis",
    "nginx": "nginx",
    "httpd": "apache",
    "php": "php",
    "ruby": "ruby",
    "golang": "go",
    "go": "go",
    "django": "django",
    "rails": "rails",
    "ubuntu": "ubuntu",
    "debian": "debian",
    "alpine": "alpine",
    "elasticsearch": "elasticsearch",
    "rabbitmq": "rabbitmq",
    "mongo": "mongodb",
    "mongodb": "mongodb",
    "dotnet": "dotnet",
    "grafana": "grafana",
    "prometheus": "prometheus",
    "kafka": "kafka",
    "cassandra": "cassandra",
    "erlang": "erlang",
    "haproxy": "haproxy",
    "jenkins": "jenkins",
    "traefik": "traefik",
}


def _version_parts(version: str) -> tuple[int, ...]:
    """Parse the leading numeric dot-separated segments of a version string."""
    parts: list[int] = []
    for segment in version.split("."):
        if segment.isdigit():
            parts.append(int(segment))
        else:
            break
    return tuple(parts)


def _cycle_matches(version: str, cycle: str) -> bool:
    """True if `version` falls under endoflife.date `cycle`, using SemVer-aware
    segment comparison (not naive substring prefix matching)."""
    vparts = _version_parts(version)
    cparts = _version_parts(cycle)
    if not vparts or not cparts:
        return version == cycle
    if len(cparts) > len(vparts):
        return False
    return vparts[: len(cparts)] == cparts


class EndOfLifeChecker(EOLCheckerInterface):
    BASE_URL = "https://endoflife.date/api"

    def __init__(
        self,
        timeout: int = 15,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_base: float = DEFAULT_BACKOFF_BASE,
    ):
        self._timeout = timeout
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base
        self._cache: dict[str, list[dict[str, Any]]] = {}

    def _resolve_product(self, product: str) -> str:
        return DOCKER_TO_ENDOFLIFE.get(product.lower(), product.lower())

    async def _fetch_product(self, product: str) -> list[dict[str, Any]]:
        policy = retry_policy(self._max_attempts, self._backoff_base)
        result: list[dict[str, Any]] = await policy(self._fetch_product_once, product)
        return result

    async def _fetch_product_once(self, product: str) -> list[dict[str, Any]]:
        slug = self._resolve_product(product)
        if slug in self._cache:
            return self._cache[slug]
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                resp = await client.get(f"{self.BASE_URL}/{slug}.json")
                if resp.status_code == 200:
                    data = cast("list[dict[str, Any]]", resp.json())
                    self._cache[slug] = data
                    return data
                return []
            except httpx.HTTPError as e:
                logger.debug(f"EOL check failed for {slug}: {e}")
                return []

    def _find_cycle(self, cycles: list[dict[str, Any]], version: str) -> dict[str, Any] | None:
        best: dict[str, Any] | None = None
        best_len = -1
        for cycle in cycles:
            cycle_ver = str(cycle.get("cycle", ""))
            if _cycle_matches(version, cycle_ver):
                clen = len(_version_parts(cycle_ver))
                if clen > best_len:
                    best = cycle
                    best_len = clen
        return best

    async def is_eol(self, product: str, version: str) -> bool:
        if not version:
            return False
        cycles = await self._fetch_product(product)
        cycle = self._find_cycle(cycles, version)
        if cycle is None:
            return False
        eol = cycle.get("eol")
        if isinstance(eol, bool):
            return eol
        if isinstance(eol, str):
            try:
                eol_date = datetime.strptime(eol, "%Y-%m-%d").replace(tzinfo=UTC)
                return datetime.now(tz=UTC) > eol_date
            except ValueError:
                return False
        return False

    async def is_lts(self, product: str, version: str) -> bool:
        if not version:
            return False
        cycles = await self._fetch_product(product)
        cycle = self._find_cycle(cycles, version)
        if cycle is None:
            return False
        return bool(cycle.get("lts", False))
