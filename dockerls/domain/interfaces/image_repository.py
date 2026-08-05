from __future__ import annotations

from abc import ABC, abstractmethod

from dockerls.domain.entities.image import DockerImage


class ImageRepositoryInterface(ABC):
    @abstractmethod
    async def search_tags(self, image_name: str, limit: int = 100) -> list[DockerImage]:
        ...

    @abstractmethod
    async def get_image_metadata(self, image_name: str, tag: str) -> DockerImage | None:
        ...
