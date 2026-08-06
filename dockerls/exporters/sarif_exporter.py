from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from dockerls import __version__
from dockerls.domain.entities.vulnerability import Severity
from dockerls.exporters.base import ExporterInterface

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis

_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.UNKNOWN: "note",
}


class SARIFExporter(ExporterInterface):
    """Exports scan findings as SARIF 2.1.0 for consumption by GitHub code
    scanning and other SARIF-aware tooling."""

    def export(self, result: AnalysisResult, output_path: Path) -> None:
        output_path.write_text(self.export_string(result), encoding="utf-8")

    def export_string(self, result: AnalysisResult) -> str:
        images: list[ImageAnalysis] = [*result.recommendations, *result.alternatives]
        rules: dict[str, dict[str, Any]] = {}
        sarif_results: list[dict[str, Any]] = []

        for analysis in images:
            for vuln in analysis.scan.vulnerabilities:
                if vuln.cve_id not in rules:
                    rules[vuln.cve_id] = {
                        "id": vuln.cve_id,
                        "shortDescription": {"text": vuln.description or vuln.cve_id},
                        "helpUri": f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}",
                        "properties": {
                            "security-severity": str(vuln.cvss_score),
                            "tags": ["security", vuln.severity.value],
                        },
                    }
                sarif_results.append(
                    {
                        "ruleId": vuln.cve_id,
                        "level": _SEVERITY_TO_LEVEL.get(vuln.severity, "warning"),
                        "message": {
                            "text": (
                                f"{vuln.severity.value} vulnerability in "
                                f"{vuln.package_name} {vuln.installed_version}"
                                + (f" (fix: {vuln.fixed_version})" if vuln.fixed_version else "")
                            )
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": analysis.image.full_reference}
                                }
                            }
                        ],
                    }
                )

        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "DockerLs",
                            "informationUri": "https://github.com/GhostN3xus/DockerLs",
                            "version": __version__,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }
        return json.dumps(sarif, indent=2, default=str)
