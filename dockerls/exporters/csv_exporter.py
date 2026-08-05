from __future__ import annotations

import csv
import io
from pathlib import Path

from dockerls.application.dto.analysis import AnalysisResult
from dockerls.exporters.base import ExporterInterface


class CSVExporter(ExporterInterface):
    def export(self, result: AnalysisResult, output_path: Path) -> None:
        output_path.write_text(self.export_string(result), encoding="utf-8")

    def export_string(self, result: AnalysisResult) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Image", "Tag", "Score", "Tier", "Critical", "High",
            "Medium", "Low", "Fixable", "Remediation Score", "EOL", "LTS",
        ])
        for a in result.recommendations or result.alternatives:
            writer.writerow([
                a.image.name, a.image.tag, a.security_score, a.tier,
                a.scan.critical_count, a.scan.high_count, a.scan.medium_count,
                a.scan.low_count, a.scan.fixable_count, a.remediation_score,
                a.is_eol, a.is_lts,
            ])
        return output.getvalue()
