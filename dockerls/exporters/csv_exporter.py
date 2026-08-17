from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING

from dockerls.exporters.base import ExporterInterface

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.application.dto.analysis import AnalysisResult


class CSVExporter(ExporterInterface):
    def export(self, result: AnalysisResult, output_path: Path) -> None:
        output_path.write_bytes(self.export_string(result).encode("utf-8"))

    def export_string(self, result: AnalysisResult) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "Image",
                "Tag",
                "Score",
                "Tier",
                "Critical",
                "High",
                "Medium",
                "Low",
                "Fixable",
                "Remediation Score",
                "EOL",
                "LTS",
                # Appended, never inserted: a consumer indexing by column
                # position keeps working, and one reading the header gets
                # the new dimensions.
                "Source",
                "Digest",
                "Pinned Reference",
                "Hardening",
                "Hardening Coverage",
                "Attack Surface",
                "Confidence",
            ]
        )
        for a in result.recommendations or result.alternatives:
            writer.writerow(
                [
                    a.image.name,
                    a.image.tag,
                    a.security_score,
                    a.tier,
                    a.scan.critical_count,
                    a.scan.high_count,
                    a.scan.medium_count,
                    a.scan.low_count,
                    a.scan.fixable_count,
                    a.remediation_score,
                    a.is_eol,
                    a.is_lts,
                    a.image.source,
                    a.image.digest,
                    a.pinned_reference,
                    # "" rather than 0 when coverage was too thin: a zero
                    # here would be read as "no hardening", which is the
                    # opposite of "not determined".
                    a.hardening.score if a.hardening.reportable else "",
                    a.hardening.coverage,
                    a.attack_surface.score if a.attack_surface.reportable else "",
                    a.confidence.value,
                ]
            )
        return output.getvalue()
