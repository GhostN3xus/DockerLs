from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime
from typing import Any

import httpx
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from dockerls.utils.validation import sanitize_image_name


class DockerHubClient(ImageRepositoryInterface):
    BASE_URL = "https://hub.docker.com/v2"

    def __init__(self, username: str = "", token: str = "", timeout: int = 30):
        self._username = username
        self._token = token
        self._timeout = timeout
        self._auth_token: str = ""

    async def _get_client(self) -> httpx.AsyncClient:
        headers = {"Accept": "application/json"}
        if self._auth_token:
            headers["Authorization"] = f"Bearer {self._auth_token}"
        return httpx.AsyncClient(
            timeout=self._timeout,
            headers=headers,
            follow_redirects=True,
        )

    async def authenticate(self) -> bool:
        if not self._username or not self._token:
            return False
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self.BASE_URL}/users/login/",
                    json={"username": self._username, "password": self._token},
                )
                if resp.status_code == 200:
                    self._auth_token = resp.json().get("token", "")
                    return bool(self._auth_token)
        except httpx.HTTPError as e:
            logger.warning(f"Docker Hub auth failed: {e}")
        return False

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
    async def _get_json(self, client: httpx.AsyncClient, url: str) -> httpx.Response:
        """Perform a single GET with retry scoped to *this* request only, so
        a transient failure deep into a paginated fetch doesn't force the
        whole listing to restart from page one. Honors Retry-After on 429."""
        resp = await client.get(url)
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            wait_s = float(retry_after) if retry_after and retry_after.isdigit() else 2.0
            logger.warning(f"Rate limited by Docker Hub, waiting {wait_s}s")
            await asyncio.sleep(wait_s)
            resp.raise_for_status()
        return resp

    @staticmethod
    def _parse_images(images: list[dict[str, Any]]) -> tuple[int, str, str, list[str]]:
        """Return (size, digest, primary_architecture, all_architectures)."""
        archs = [img.get("architecture", "unknown") for img in images]
        for img in images:
            if img.get("architecture") == "amd64":
                return img.get("size", 0), img.get("digest", ""), "amd64", archs
        if images:
            first = images[0]
            return (
                first.get("size", 0),
                first.get("digest", ""),
                first.get("architecture", "unknown"),
                archs,
            )
        return 0, "", "amd64", archs

    async def search_tags(self, image_name: str, limit: int = 100) -> list[DockerImage]:
        safe_name = sanitize_image_name(image_name)
        namespace = "library" if "/" not in safe_name else safe_name.split("/")[0]
        repo = safe_name if "/" not in safe_name else safe_name.split("/", 1)[1]

        tags: list[DockerImage] = []
        page_size = min(limit, 100)
        url: str | None = (
            f"{self.BASE_URL}/repositories/{namespace}/{repo}/tags/"
            f"?page_size={page_size}&ordering=last_updated"
        )

        async with await self._get_client() as client:
            while url and len(tags) < limit:
                try:
                    resp = await self._get_json(client, url)
                    if resp.status_code == 404:
                        logger.warning(f"Image not found: {safe_name}")
                        return []
                    resp.raise_for_status()
                    data = resp.json()

                    for tag_data in data.get("results", []):
                        tag_name = tag_data.get("name", "")
                        if not tag_name:
                            continue

                        last_updated = None
                        lu_str = tag_data.get("last_updated")
                        if lu_str:
                            with contextlib.suppress(ValueError):
                                last_updated = datetime.fromisoformat(lu_str.replace("Z", "+00:00"))

                        size, digest, arch, archs = self._parse_images(tag_data.get("images", []))

                        tags.append(
                            DockerImage(
                                name=safe_name,
                                tag=tag_name,
                                digest=digest,
                                size_bytes=size,
                                architecture=arch,
                                available_architectures=archs,
                                last_updated=last_updated,
                                is_official=namespace == "library",
                            )
                        )

                    url = data.get("next")
                except httpx.HTTPError as e:
                    # Network blips or non-429 API errors degrade to a
                    # partial result (whatever pages already fetched)
                    # instead of crashing the whole search.
                    logger.error(f"Docker Hub API error, returning partial results: {e}")
                    break

        return tags[:limit]

    async def get_image_metadata(self, image_name: str, tag: str) -> DockerImage | None:
        safe_name = sanitize_image_name(image_name)
        namespace = "library" if "/" not in safe_name else safe_name.split("/")[0]
        repo = safe_name if "/" not in safe_name else safe_name.split("/", 1)[1]

        url = f"{self.BASE_URL}/repositories/{namespace}/{repo}/tags/{tag}"

        async with await self._get_client() as client:
            try:
                resp = await self._get_json(client, url)
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                data = resp.json()

                last_updated = None
                lu_str = data.get("last_updated")
                if lu_str:
                    with contextlib.suppress(ValueError):
                        last_updated = datetime.fromisoformat(lu_str.replace("Z", "+00:00"))

                size, digest, arch, archs = self._parse_images(data.get("images", []))

                return DockerImage(
                    name=safe_name,
                    tag=tag,
                    digest=digest,
                    size_bytes=size,
                    architecture=arch,
                    available_architectures=archs,
                    last_updated=last_updated,
                    is_official=namespace == "library",
                )
            except httpx.HTTPError as e:
                logger.error(f"Failed to get metadata for {safe_name}:{tag}: {e}")
                return None
