from __future__ import annotations

from datetime import datetime

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
            timeout=self._timeout, headers=headers, follow_redirects=True,
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
                    resp = await client.get(url)
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
                            try:
                                last_updated = datetime.fromisoformat(
                                    lu_str.replace("Z", "+00:00")
                                )
                            except ValueError:
                                pass

                        size = 0
                        digest = ""
                        arch = "amd64"
                        for img in tag_data.get("images", []):
                            if img.get("architecture") == "amd64":
                                size = img.get("size", 0)
                                digest = img.get("digest", "")
                                arch = "amd64"
                                break
                        if not digest and tag_data.get("images"):
                            first = tag_data["images"][0]
                            size = first.get("size", 0)
                            digest = first.get("digest", "")
                            arch = first.get("architecture", "unknown")

                        tags.append(
                            DockerImage(
                                name=safe_name,
                                tag=tag_name,
                                digest=digest,
                                size_bytes=size,
                                architecture=arch,
                                last_updated=last_updated,
                                is_official=namespace == "library",
                            )
                        )

                    url = data.get("next")
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 429:
                        logger.warning("Rate limited by Docker Hub")
                        raise
                    logger.error(f"Docker Hub API error: {e}")
                    break

        return tags[:limit]

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
    async def get_image_metadata(self, image_name: str, tag: str) -> DockerImage | None:
        safe_name = sanitize_image_name(image_name)
        namespace = "library" if "/" not in safe_name else safe_name.split("/")[0]
        repo = safe_name if "/" not in safe_name else safe_name.split("/", 1)[1]

        url = f"{self.BASE_URL}/repositories/{namespace}/{repo}/tags/{tag}"

        async with await self._get_client() as client:
            try:
                resp = await client.get(url)
                if resp.status_code == 404:
                    return None
                resp.raise_for_status()
                data = resp.json()

                last_updated = None
                lu_str = data.get("last_updated")
                if lu_str:
                    try:
                        last_updated = datetime.fromisoformat(
                            lu_str.replace("Z", "+00:00")
                        )
                    except ValueError:
                        pass

                size = 0
                digest = ""
                for img in data.get("images", []):
                    if img.get("architecture") == "amd64":
                        size = img.get("size", 0)
                        digest = img.get("digest", "")
                        break

                return DockerImage(
                    name=safe_name,
                    tag=tag,
                    digest=digest,
                    size_bytes=size,
                    last_updated=last_updated,
                    is_official=namespace == "library",
                )
            except httpx.HTTPError as e:
                logger.error(f"Failed to get metadata for {safe_name}:{tag}: {e}")
                return None
