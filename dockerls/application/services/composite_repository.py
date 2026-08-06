from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface

if TYPE_CHECKING:
    from dockerls.domain.entities.image import DockerImage


class CompositeImageRepository(ImageRepositoryInterface):
    """Fans a query out across every configured image source.

    The primary source (Docker Hub) sets the bulk of the candidate list;
    hardened catalogues contribute a small number of tags each. All of them
    feed the same scan pipeline, so a hardened image wins on measured
    vulnerabilities rather than on reputation.

    A source that fails is logged and skipped -- one unreachable registry
    must not take down a search the other sources can still answer.
    """

    def __init__(
        self,
        primary: ImageRepositoryInterface,
        extra: list[ImageRepositoryInterface] | None = None,
        extra_limit: int = 10,
    ):
        self._primary = primary
        self._extra = extra or []
        self._extra_limit = extra_limit

    @property
    def sources(self) -> list[ImageRepositoryInterface]:
        return [self._primary, *self._extra]

    async def search_tags(self, image_name: str, limit: int = 100) -> list[DockerImage]:
        async def safe(repo: ImageRepositoryInterface, per_source_limit: int) -> list[DockerImage]:
            try:
                return await repo.search_tags(image_name, limit=per_source_limit)
            except Exception as e:
                logger.warning(f"{type(repo).__name__} search failed for {image_name}: {e}")
                return []

        results = await asyncio.gather(
            safe(self._primary, limit),
            *[safe(repo, self._extra_limit) for repo in self._extra],
        )

        merged: list[DockerImage] = []
        seen: set[str] = set()
        for source_tags in results:
            for image in source_tags:
                if image.full_reference in seen:
                    continue
                seen.add(image.full_reference)
                merged.append(image)
        return merged

    async def get_image_metadata(self, image_name: str, tag: str) -> DockerImage | None:
        for repo in self.sources:
            try:
                found = await repo.get_image_metadata(image_name, tag)
            except Exception as e:
                logger.warning(f"{type(repo).__name__} metadata failed for {image_name}: {e}")
                continue
            if found is not None:
                return found
        return None

    async def tag_exists(self, image_name: str, tag: str) -> bool | None:
        """Route the check to the source that owns the reference.

        `image_name` here is the fully-qualified name the pipeline scanned
        (e.g. "cgr.dev/chainguard/node"), so the owning source is whichever
        one recognises it.
        """
        for repo in self.sources:
            host = getattr(repo, "host", "")
            if host and image_name.startswith(f"{host}/"):
                return await _safe_tag_exists(repo, _strip_host(image_name, host), tag)
        return await _safe_tag_exists(self._primary, image_name, tag)


def _strip_host(image_name: str, host: str) -> str:
    """Turn "cgr.dev/chainguard/node" back into the bare query "node" the
    source's own `repository_for()` expects."""
    remainder = image_name[len(host) + 1 :]
    return remainder.split("/", 1)[1] if "/" in remainder else remainder


async def _safe_tag_exists(
    repo: ImageRepositoryInterface, image_name: str, tag: str
) -> bool | None:
    checker = getattr(repo, "tag_exists", None)
    if not callable(checker):
        return None
    try:
        result: bool | None = await checker(image_name, tag)
    except Exception as e:
        logger.warning(f"{type(repo).__name__} tag check failed for {image_name}:{tag}: {e}")
        return None
    return result
