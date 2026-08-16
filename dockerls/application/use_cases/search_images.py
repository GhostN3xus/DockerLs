from __future__ import annotations

from typing import TYPE_CHECKING

from dockerls.application.services.teardown import close_quietly, sources_of

if TYPE_CHECKING:
    from dockerls.domain.entities.image import DockerImage
    from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface


class SearchImagesUseCase:
    def __init__(self, repository: ImageRepositoryInterface):
        self._repository = repository

    async def execute(self, image_name: str, limit: int = 100) -> list[DockerImage]:
        try:
            return await self._repository.search_tags(image_name, limit=limit)
        finally:
            # The repository keeps one connection pool alive for the whole
            # run so requests can reuse it, which makes handing it back the
            # caller's job rather than a context manager's.
            await close_quietly(*sources_of(self._repository))
