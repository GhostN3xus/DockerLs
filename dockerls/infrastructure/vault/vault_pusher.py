"""Writes a build's hardening report into an Obsidian-style notes vault.

The vault is a directory of Markdown files, so this is a file writer with
one job beyond writing: it must never let a caller-supplied vault path or
image tag steer a write outside the vault root.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.infrastructure.evidence import slugify_reference

if TYPE_CHECKING:
    from dockerls.application.dto.build import BuildReport


class VaultPushError(RuntimeError):
    """The report could not be written where the caller asked."""


class VaultPusher:
    def __init__(self, root: Path):
        self._root = root.expanduser()

    @property
    def root(self) -> Path:
        return self._root

    async def push(self, report: BuildReport, relative_path: str) -> str:
        return await asyncio.to_thread(self._push_sync, report, relative_path)

    def _push_sync(self, report: BuildReport, relative_path: str) -> str:
        target_dir = self._resolve(relative_path)
        stamp = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%S")
        name = f"{slugify_reference(report.image or report.build_id)}__{stamp}.md"
        path = target_dir / name
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(render_vault_note(report), encoding="utf-8")
        except OSError as e:
            raise VaultPushError(f"Could not write vault note to {path}: {e}") from e
        logger.info(f"Build report pushed to vault: {path}")
        return str(path)

    def _resolve(self, relative_path: str) -> Path:
        """Join `relative_path` under the vault root, refusing anything that
        escapes it -- an absolute path or a `../` traversal."""
        candidate = Path(relative_path)
        if candidate.is_absolute():
            raise VaultPushError(f"Vault path must be relative to the vault root: {relative_path}")
        resolved = (self._root / candidate).resolve()
        root = self._root.resolve()
        if resolved != root and root not in resolved.parents:
            raise VaultPushError(f"Vault path escapes the vault root: {relative_path}")
        return resolved


def render_vault_note(report: BuildReport) -> str:
    """The Markdown body of one build's note."""
    meta = report.build_metadata
    lines = [
        f"# {report.image or 'build'} -- Build Hardening Report",
        "",
        f"**Date:** {meta.timestamp}",
        f"**Git SHA:** {meta.git_sha or 'unknown'}",
        f"**Security Score:** {report.security_score}/100",
        f"**Tier:** {report.security_tier} ({report.tier_advice})",
        f"**Status:** {report.status}",
        "",
        "## Validation",
    ]
    for check in report.validation.checks:
        location = f" (line {check.line})" if check.line else ""
        lines.append(f"- **{check.status.value}** `{check.check}`{location} -- {check.message}")

    if report.scans:
        lines += ["", "## Scan Results"]
        for scan in report.scans:
            lines.append(
                f"- **{scan.scanner}**: {scan.critical} critical, {scan.high} high, "
                f"{scan.medium} medium, {scan.low} low ({scan.fixable} fixable)"
            )

    if report.recommendations:
        lines += ["", "## Recommendations"]
        for i, rec in enumerate(report.recommendations, 1):
            lines.append(f"{i}. **[{rec.priority.value}] {rec.title}** -- {rec.reason}")
            if rec.suggested:
                lines.append(f"   - Suggested: `{rec.suggested}`")

    lines += ["", "## Evidence"]
    for scan in report.scans:
        if scan.evidence_path:
            lines.append(f"- {scan.scanner} scan: `{scan.evidence_path}`")
    if report.sbom and report.sbom.file:
        lines.append(f"- SBOM ({report.sbom.fmt}): `{report.sbom.file}`")
    if report.report_file:
        lines.append(f"- Full report: `{report.report_file}`")
    if report.log_file:
        lines.append(f"- Build log: `{report.log_file}`")
    if len(lines) and lines[-1] == "## Evidence":
        lines.append("- No evidence artefacts were produced for this run.")

    lines.append("")
    return "\n".join(lines)
