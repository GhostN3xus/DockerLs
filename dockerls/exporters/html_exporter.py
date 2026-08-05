from __future__ import annotations

from pathlib import Path

from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis
from dockerls.exporters.base import ExporterInterface


class HTMLExporter(ExporterInterface):
    def export(self, result: AnalysisResult, output_path: Path) -> None:
        output_path.write_text(self.export_string(result), encoding="utf-8")

    def export_string(self, result: AnalysisResult) -> str:
        items = result.recommendations or result.alternatives
        rows = "\n".join(self._row(a) for a in items)
        status = "Baseline Met" if result.baseline_met else "Alternative Recommendations"
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DockerLs Report - {_esc(result.query)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #fafafa; color: #1a1a1a; }}
h1 {{ border-bottom: 2px solid #333; padding-bottom: .5rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
th {{ background: #333; color: #fff; }}
tr:nth-child(even) {{ background: #f2f2f2; }}
.s {{ color: #16a34a; font-weight: bold; }}
.a {{ color: #2563eb; font-weight: bold; }}
.b {{ color: #d97706; font-weight: bold; }}
.c {{ color: #dc2626; font-weight: bold; }}
.info {{ background: #fff; padding: 1rem; border: 1px solid #ddd; border-radius: 4px; margin: 1rem 0; }}
</style>
</head>
<body>
<h1>DockerLs Security Report</h1>
<div class="info">
<p><strong>Query:</strong> {_esc(result.query)}</p>
<p><strong>Tags Scanned:</strong> {result.total_tags_scanned}</p>
<p><strong>Status:</strong> {status}</p>
</div>
<table>
<thead><tr>
<th>Image</th><th>Score</th><th>Tier</th>
<th>Critical</th><th>High</th><th>Medium</th><th>Low</th>
<th>Fixable</th><th>Remediation</th><th>EOL</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
</body>
</html>"""

    def _row(self, a: ImageAnalysis) -> str:
        t = a.tier.lower()
        return (
            f'<tr><td>{_esc(a.image.full_reference)}</td><td>{a.security_score}</td>'
            f'<td class="{t}">{a.tier}</td>'
            f'<td>{a.scan.critical_count}</td><td>{a.scan.high_count}</td>'
            f'<td>{a.scan.medium_count}</td><td>{a.scan.low_count}</td>'
            f'<td>{a.scan.fixable_count}</td><td>{a.remediation_score}%</td>'
            f'<td>{"Yes" if a.is_eol else "No"}</td></tr>'
        )


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
