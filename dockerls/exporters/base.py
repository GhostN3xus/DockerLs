from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.application.dto.analysis import AnalysisResult


class ExporterInterface(ABC):
    @abstractmethod
    def export(self, result: AnalysisResult, output_path: Path) -> None: ...

    @abstractmethod
    def export_string(self, result: AnalysisResult) -> str: ...
