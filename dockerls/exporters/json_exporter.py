from __future__ import annotations

import json
from typing import TYPE_CHECKING

from dockerls.exporters.base import ExporterInterface

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.application.dto.analysis import AnalysisResult


class JSONExporter(ExporterInterface):
    def export(self, result: AnalysisResult, output_path: Path) -> None:
        output_path.write_bytes(self.export_string(result).encode("utf-8"))

    def export_string(self, result: AnalysisResult) -> str:
        return json.dumps(result.model_dump(), indent=2, default=str)
