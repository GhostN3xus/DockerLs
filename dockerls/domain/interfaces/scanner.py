from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dockerls.domain.entities.scan_result import ScanResult


class ScannerInterface(ABC):
    @abstractmethod
    async def scan(self, image_reference: str, platform: str | None = None) -> ScanResult:
        """Measure `image_reference`.

        `platform` is `os/architecture[/variant]`. When given it is passed to
        the tool so a multi-arch reference is measured for *that* platform; a
        scanner that cannot honour it must fail rather than measure the host's
        platform and let the result be filed under another one.
        """

    @abstractmethod
    async def is_available(self) -> bool: ...
