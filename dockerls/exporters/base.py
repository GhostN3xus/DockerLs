from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.application.dto.analysis import AnalysisResult


class ExporterInterface(ABC):
    def export(self, result: AnalysisResult, output_path: Path) -> None:
        output_path.write_bytes(self.export_string(result).encode("utf-8"))

    @abstractmethod
    def export_string(self, result: AnalysisResult) -> str: ...
