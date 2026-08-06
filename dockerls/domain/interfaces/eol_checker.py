from __future__ import annotations

from abc import ABC, abstractmethod


class EOLCheckerInterface(ABC):
    @abstractmethod
    async def is_eol(self, product: str, version: str) -> bool: ...

    @abstractmethod
    async def is_lts(self, product: str, version: str) -> bool: ...
