from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dockerls.application.dto.build import BuildOptions, BuildResult


class ImageBuilderInterface(ABC):
    """Builds and publishes container images."""

    @abstractmethod
    async def is_available(self) -> bool:
        """Whether the underlying build engine can be reached at all."""

    @abstractmethod
    async def build(self, options: BuildOptions) -> BuildResult:
        """Build one image. Never raises for a failed build -- a build that
        the engine rejected is a `BuildResult` with `success=False`, so the
        caller can still report validation findings alongside the error."""

    @abstractmethod
    async def push(self, tag: str) -> tuple[bool, str]:
        """Push `tag` to its registry. Returns (ok, message)."""
