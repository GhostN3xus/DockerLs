"""Renderers for a `BuildReport`.

Separate from the `recommend` exporters because the two describe different
things: those rank candidate images, these record one build. Sharing an
interface between them would force one of the two to render fields that do
not apply to it.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from dockerls import __version__
from dockerls.domain.entities.build_validation import CheckStatus
from dockerls.domain.entities.vulnerability import Severity

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.application.dto.build import BuildReport
    from dockerls.domain.entities.build_validation import ValidationCheck

_SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.UNKNOWN: "note",
}

_STATUS_SYMBOL = {
    CheckStatus.PASS: "PASS",
    CheckStatus.WARN: "WARN",
    CheckStatus.FAIL: "FAIL",
    CheckStatus.SKIP: "SKIP",
}


class BuildReportExporter(ABC):
    @abstractmethod
    def export_string(self, report: BuildReport) -> str: ...

    def export(self, report: BuildReport, output_path: Path) -> None:
        output_path.write_text(self.export_string(report), encoding="utf-8")


class JSONBuildReportExporter(BuildReportExporter):
    def export_string(self, report: BuildReport) -> str:
        return json.dumps(report.model_dump(mode="json"), indent=2, default=str)


class MarkdownBuildReportExporter(BuildReportExporter):
    def export_string(self, report: BuildReport) -> str:
        v = report.validation
        lines = [
            f"# Build Report -- {report.image or report.build_id}",
            "",
            f"- **Status:** {report.status}" + (f" ({report.reason})" if report.reason else ""),
            f"- **Security score:** {report.security_score}/100 (tier {report.security_tier})",
            f"- **Dockerfile:** `{report.dockerfile_path}`",
            f"- **Build id:** `{report.build_id}`",
            f"- **Git SHA:** `{report.build_metadata.git_sha or 'unknown'}`",
            "",
            f"- **Validation:** {report.validation_passed} passed, "
            f"{report.validation_warnings} warning(s), {report.validation_errors} error(s)",
            "",
            f"## Validation ({len(v.passed)}/{v.evaluated_count} passed)",
            "",
            "| Rule | Status | Severity | Line | Detail |",
            "| --- | --- | --- | --- | --- |",
        ]
        for check in v.checks:
            line = str(check.line) if check.line else "-"
            lines.append(
                f"| `{check.check}` | {_STATUS_SYMBOL[check.status]} | "
                f"{check.severity.value} | {line} | {_md_cell(check.message)} |"
            )

        if report.scans:
            lines += [
                "",
                "## Scan Results",
                "",
                "| Scanner | Critical | High | Medium | Low | Fixable |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
            for scan in report.scans:
                lines.append(
                    f"| {scan.scanner} | {scan.critical} | {scan.high} | "
                    f"{scan.medium} | {scan.low} | {scan.fixable} |"
                )

        if report.failing_vulnerabilities:
            lines += [
                "",
                "## Findings above the fail-on threshold",
                "",
                "| CVE | Severity | Package | Fix |",
                "| --- | --- | --- | --- |",
            ]
            for vuln in report.failing_vulnerabilities:
                fix = vuln.fixed_version or ("available" if vuln.fixable else "none")
                lines.append(f"| {vuln.cve} | {vuln.severity} | {vuln.package} | {fix} |")

        if report.recommendations:
            lines += ["", "## Recommendations", ""]
            for rec in report.recommendations:
                lines.append(f"- **[{rec.priority.value}] {rec.title}** -- {rec.reason}")

        lines.append("")
        return "\n".join(lines)


class HTMLBuildReportExporter(BuildReportExporter):
    def export_string(self, report: BuildReport) -> str:
        v = report.validation
        rows = "\n".join(self._check_row(c) for c in v.checks)
        scan_rows = "\n".join(
            f"<tr><td>{_esc(s.scanner)}</td><td>{s.critical}</td><td>{s.high}</td>"
            f"<td>{s.medium}</td><td>{s.low}</td><td>{s.fixable}</td></tr>"
            for s in report.scans
        )
        scan_section = (
            f"""<h2>Scan Results</h2>
<table><thead><tr><th>Scanner</th><th>Critical</th><th>High</th>
<th>Medium</th><th>Low</th><th>Fixable</th></tr></thead>
<tbody>{scan_rows}</tbody></table>"""
            if scan_rows
            else '<h2>Scan Results</h2><p class="muted">No post-build scan was run.</p>'
        )
        recommendations = "\n".join(
            f"<li><strong>[{_esc(r.priority.value)}] {_esc(r.title)}</strong> &mdash; "
            f"{_esc(r.reason)}"
            + (f"<pre>{_esc(r.suggested)}</pre>" if r.suggested else "")
            + "</li>"
            for r in report.recommendations
        )
        recommendations_block = (
            f"<ul>{recommendations}</ul>"
            if recommendations
            else '<p class="muted">Nothing further to harden.</p>'
        )
        build = report.build
        build_rows = (
            f"<p><strong>Image:</strong> {_esc(build.image_id or '-')}<br>"
            f"<strong>Size:</strong> {_esc(build.size_human)} &nbsp;|&nbsp; "
            f"<strong>Layers:</strong> {build.layer_count} &nbsp;|&nbsp; "
            f"<strong>Duration:</strong> {build.duration_seconds}s</p>"
            if build is not None
            else '<p class="muted">No image was built.</p>'
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DockerLs Build Report - {_esc(report.image or report.build_id)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #fafafa;
  color: #1a1a1a; line-height: 1.5; }}
h1 {{ border-bottom: 2px solid #333; padding-bottom: .5rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left;
  vertical-align: top; }}
th {{ background: #333; color: #fff; }}
tr:nth-child(even) {{ background: #f2f2f2; }}
pre {{ background: #1a1a1a; color: #eee; padding: .75rem; border-radius: 4px;
  overflow-x: auto; font-size: .85rem; }}
.info {{ background: #fff; padding: 1rem; border: 1px solid #ddd;
  border-radius: 4px; margin: 1rem 0; }}
.muted {{ color: #666; }}
.pass {{ color: #16a34a; font-weight: bold; }}
.warn {{ color: #d97706; font-weight: bold; }}
.fail {{ color: #dc2626; font-weight: bold; }}
.skip {{ color: #666; }}
.tier {{ font-size: 2rem; font-weight: bold; }}
.s, .a {{ color: #16a34a; }}
.b {{ color: #d97706; }}
.c {{ color: #dc2626; }}
</style>
</head>
<body>
<h1>DockerLs Build Report</h1>
<div class="info">
<p><strong>Image:</strong> {_esc(report.image or "(not tagged)")}</p>
<p><strong>Dockerfile:</strong> {_esc(report.dockerfile_path)}</p>
<p><strong>Status:</strong> {_esc(report.status)}
{f"&mdash; {_esc(report.reason)}" if report.reason else ""}</p>
<p class="tier {report.security_tier.lower()}">{report.security_score}/100
&nbsp;Tier {_esc(report.security_tier)}</p>
<p class="muted">{_esc(report.tier_advice)}</p>
<p class="muted">Dockerfile score {report.dockerfile_score}
{f"&nbsp;|&nbsp; scan score {report.scan_score}" if report.scan_score is not None else ""}
&nbsp;|&nbsp; build {_esc(report.build_id)}
&nbsp;|&nbsp; git {_esc(report.build_metadata.git_sha[:12] or "unknown")}</p>
{build_rows}
</div>

<h2>Dockerfile Validation ({len(v.passed)}/{v.evaluated_count} passed)</h2>
<table>
<thead><tr><th>Rule</th><th>Status</th><th>Severity</th><th>Line</th>
<th>Detail</th><th>Fix</th></tr></thead>
<tbody>{rows}</tbody>
</table>

{scan_section}

<h2>Recommendations</h2>
{recommendations_block}

<p class="muted">Generated by DockerLs {_esc(__version__)}
at {_esc(report.build_metadata.timestamp)}</p>
</body>
</html>"""

    def _check_row(self, check: ValidationCheck) -> str:
        css = check.status.value.lower()
        line = str(check.line) if check.line else "-"
        fix = f"<pre>{_esc(check.fix)}</pre>" if check.fix else ""
        return (
            f"<tr><td><code>{_esc(check.check)}</code><br>"
            f'<span class="muted">{_esc(check.title)}</span></td>'
            f'<td class="{css}">{_esc(check.status.value)}</td>'
            f"<td>{_esc(check.severity.value)}</td><td>{line}</td>"
            f"<td>{_esc(check.message)}</td><td>{fix}</td></tr>"
        )


class SARIFBuildReportExporter(BuildReportExporter):
    """SARIF 2.1.0 for GitHub code scanning.

    Validation findings are anchored to the Dockerfile's line, which is what
    makes them show up as annotations on the pull request that introduced
    them. Vulnerabilities have no source line, so they anchor to the file as
    a whole.
    """

    def export_string(self, report: BuildReport) -> str:
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []
        uri = _relative_uri(report.dockerfile_path, report.context_path)

        for check in report.validation.checks:
            if check.status not in (CheckStatus.FAIL, CheckStatus.WARN):
                continue
            rules.setdefault(
                check.check,
                {
                    "id": check.check,
                    "name": check.check,
                    "shortDescription": {"text": check.title or check.check},
                    "fullDescription": {"text": check.message},
                    "help": {"text": check.fix or check.message},
                    "properties": {
                        "tags": ["security", "dockerfile", check.severity.value],
                        "problem.severity": _SEVERITY_TO_SARIF_LEVEL.get(check.severity, "warning"),
                    },
                },
            )
            results.append(
                {
                    "ruleId": check.check,
                    "level": _SEVERITY_TO_SARIF_LEVEL.get(check.severity, "warning"),
                    "message": {"text": check.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                # SARIF requires startLine >= 1; a file-level
                                # finding anchors to line 1 rather than 0.
                                "region": {"startLine": max(check.line, 1)},
                            }
                        }
                    ],
                }
            )

        for vuln in report.failing_vulnerabilities:
            severity = _to_severity(vuln.severity)
            rules.setdefault(
                vuln.cve,
                {
                    "id": vuln.cve,
                    "shortDescription": {"text": f"{vuln.cve} in {vuln.package}"},
                    "helpUri": f"https://nvd.nist.gov/vuln/detail/{vuln.cve}",
                    "properties": {"tags": ["security", "vulnerability", vuln.severity]},
                },
            )
            fix = f" (fix: {vuln.fixed_version})" if vuln.fixed_version else " (no fix available)"
            results.append(
                {
                    "ruleId": vuln.cve,
                    "level": _SEVERITY_TO_SARIF_LEVEL.get(severity, "warning"),
                    "message": {
                        "text": f"{vuln.severity} vulnerability in {vuln.package} "
                        f"{vuln.installed_version}{fix}"
                    },
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
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
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2, default=str)


class BuildReportExporterFactory:
    _exporters: dict[str, type[BuildReportExporter]] = {
        "json": JSONBuildReportExporter,
        "html": HTMLBuildReportExporter,
        "sarif": SARIFBuildReportExporter,
        "markdown": MarkdownBuildReportExporter,
        "md": MarkdownBuildReportExporter,
    }

    @classmethod
    def create(cls, format_name: str) -> BuildReportExporter:
        key = format_name.lower()
        if key not in cls._exporters:
            supported = ", ".join(sorted(cls._exporters))
            raise ValueError(f"Unsupported report format: {format_name}. Supported: {supported}")
        return cls._exporters[key]()

    @classmethod
    def supported_formats(cls) -> list[str]:
        return sorted(cls._exporters)


def _to_severity(value: str) -> Severity:
    try:
        return Severity(value.upper())
    except ValueError:
        return Severity.UNKNOWN


def _relative_uri(dockerfile_path: str, context_path: str) -> str:
    """A repo-relative URI, which is what GitHub needs to place an
    annotation. Falls back to the raw path when the two are unrelated."""
    from pathlib import Path

    try:
        return Path(dockerfile_path).resolve().relative_to(Path(context_path).resolve()).as_posix()
    except (ValueError, OSError):
        return Path(dockerfile_path).name


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _md_cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")
