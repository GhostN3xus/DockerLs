from __future__ import annotations

from typing import TYPE_CHECKING

from dockerls.exporters.base import ExporterInterface

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.application.dto.analysis import AnalysisResult


class MarkdownExporter(ExporterInterface):
    def export(self, result: AnalysisResult, output_path: Path) -> None:
        output_path.write_text(self.export_string(result), encoding="utf-8")

    def export_string(self, result: AnalysisResult) -> str:
        items = result.recommendations or result.alternatives
        status = "Baseline Met" if result.baseline_met else "Alternative Recommendations"
        lines = [
            "# DockerLs Security Report",
            "",
            f"**Query:** {result.query}",
            f"**Tags Scanned:** {result.total_tags_scanned}",
            f"**Status:** {status}",
            "",
            "## Results",
            "",
            "| Image | Score | Tier | Critical | High | Medium | Low | Fixable "
            "| Remediation | EOL |",
            "|-------|-------|------|----------|------|--------|-----|---------"
            "|-------------|-----|",
        ]
        for a in items:
            eol = "Yes" if a.is_eol else "No"
            lines.append(
                f"| {a.image.full_reference} | {a.security_score} | {a.tier} "
                f"| {a.scan.critical_count} | {a.scan.high_count} "
                f"| {a.scan.medium_count} | {a.scan.low_count} "
                f"| {a.scan.fixable_count} | {a.remediation_score}/100 | {eol} |"
            )

        if items and items[0].recommendation:
            rec = items[0].recommendation
            lines += [
                "",
                "## Top Recommendation",
                "",
                f"**Image:** {rec.image_reference}",
                f"**Score:** {rec.security_score}",
                f"**Summary:** {rec.summary}",
            ]
            if rec.steps:
                lines += ["", "### Remediation Steps", ""]
                for s in rec.steps:
                    desc = s.description
                    if s.from_value and s.to_value:
                        desc += f" ({s.from_value} -> {s.to_value})"
                    lines.append(f"{s.step_number}. {desc}")

        lines.append("")
        return "\n".join(lines)
