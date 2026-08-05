from __future__ import annotations

import json
from pathlib import Path

from dockerls.application.dto.analysis import AnalysisResult
from dockerls.exporters.base import ExporterInterface


class JSONExporter(ExporterInterface):
    def export(self, result: AnalysisResult, output_path: Path) -> None:
        output_path.write_text(self.export_string(result), encoding="utf-8")

    def export_string(self, result: AnalysisResult) -> str:
        return json.dumps(result.model_dump(), indent=2, default=str)
