from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dockerls.domain.entities.image import DockerImage
    from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface


class SearchImagesUseCase:
    def __init__(self, repository: ImageRepositoryInterface):
        self._repository = repository

    async def execute(self, image_name: str, limit: int = 100) -> list[DockerImage]:
        return await self._repository.search_tags(image_name, limit=limit)
