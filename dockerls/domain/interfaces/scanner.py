from __future__ import annotations

from abc import ABC, abstractmethod

from dockerls.domain.entities.scan_result import ScanResult


class ScannerInterface(ABC):
    @abstractmethod
    async def scan(self, image_reference: str) -> ScanResult:
        ...

    @abstractmethod
    async def is_available(self) -> bool:
        ...
