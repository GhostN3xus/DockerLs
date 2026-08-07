"""`dockerls build` -- validate, build, scan, report.

The order is load-bearing. Validation runs *before* the build so a
Dockerfile that bakes in a credential never produces an image at all;
scanning runs after so the report describes what actually shipped rather
than what the Dockerfile promised.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.application.dto.build import (
    BuildImageResponse,
    BuildOptions,
    BuildResult,
)
from dockerls.application.services.build_report_generator import (
    EXIT_FAILED,
    BuildReportGenerator,
    write_sbom,
)
from dockerls.infrastructure.docker.build_metadata import collect_build_metadata
from dockerls.infrastructure.vault.vault_pusher import VaultPushError

if TYPE_CHECKING:
    from dockerls.application.dto.build import BuildImageRequest, BuildReport, SbomInfo
    from dockerls.application.use_cases.analyze_dockerfile import AnalyzeDockerfileUseCase
    from dockerls.domain.entities.scan_result import ScanResult
    from dockerls.domain.interfaces.image_builder import ImageBuilderInterface
    from dockerls.domain.interfaces.scanner import ScannerInterface
    from dockerls.exporters.build_report_exporter import BuildReportExporterFactory
    from dockerls.infrastructure.vault.vault_pusher import VaultPusher


class BuildImageUseCase:
    def __init__(
        self,
        analyzer: AnalyzeDockerfileUseCase,
        builder: ImageBuilderInterface,
        report_generator: BuildReportGenerator | None = None,
        scanner: ScannerInterface | None = None,
        secondary_scanner: ScannerInterface | None = None,
        exporter_factory: type[BuildReportExporterFactory] | None = None,
        vault: VaultPusher | None = None,
        sbom_dir: Path | None = None,
        report_dir: Path | None = None,
        sbom_formats: tuple[str, ...] = ("cyclonedx",),
        log_file: str = "",
    ):
        self._analyzer = analyzer
        self._builder = builder
        self._reports = report_generator or BuildReportGenerator()
        self._scanner = scanner
        self._secondary = secondary_scanner
        self._exporters = exporter_factory
        self._vault = vault
        self._sbom_dir = sbom_dir or Path(".dockerls") / "sboms"
        self._report_dir = report_dir or Path(".dockerls") / "reports"
        self._sbom_formats = sbom_formats
        self._log_file = log_file

    async def execute(self, request: BuildImageRequest) -> BuildImageResponse:
        analysis = self._analyzer.execute(
            Path(request.context_path),
            Path(request.dockerfile_path) if request.dockerfile_path else None,
        )
        dockerfile = Path(analysis.dockerfile_path)
        context_dir = Path(analysis.context_path)
        validation = analysis.validation
        recommendations = analysis.recommendations

        # Dry-run modes stop here: neither builds, so neither can produce a
        # scan, an SBOM or an image to push.
        if request.suggest_only or request.validate_only:
            report = self._reports.generate(
                validation=validation,
                image=request.tag,
                context_path=str(context_dir),
                recommendations=recommendations,
                metadata=await collect_build_metadata(str(context_dir), buildkit=request.buildkit),
                log_file=self._log_file,
            )
            return await self._finish(report, request)

        if validation.has_blocking_findings and not request.force:
            logger.error(
                f"Refusing to build {request.tag}: "
                f"{len(validation.blocking)} blocking validation finding(s)"
            )
            report = self._reports.generate(
                validation=validation,
                image=request.tag,
                context_path=str(context_dir),
                recommendations=recommendations,
                metadata=await collect_build_metadata(str(context_dir), buildkit=request.buildkit),
                fail_on=request.fail_on,
                log_file=self._log_file,
            )
            return await self._finish(report, request)

        build = await self._build(request, dockerfile, context_dir)

        scans: list[ScanResult] = []
        sbom: SbomInfo | None = None
        if build.success and request.scan:
            scans = await self._scan(request.tag)
        if build.success and request.generate_sbom:
            sbom = await self._sbom(request.tag)

        metadata = await collect_build_metadata(
            str(context_dir),
            docker_version=await self._docker_version(),
            buildkit=request.buildkit,
        )
        report = self._reports.generate(
            validation=validation,
            image=request.tag,
            context_path=str(context_dir),
            build=build,
            scans=scans,
            recommendations=recommendations,
            metadata=metadata,
            sbom=sbom,
            fail_on=request.fail_on,
            log_file=self._log_file,
        )

        return await self._finish(report, request)

    async def _finish(self, report: BuildReport, request: BuildImageRequest) -> BuildImageResponse:
        """The single exit every path takes: write the reports, then settle
        `--push`.

        Routed through one place so a run that never got as far as building
        still *answers* `--push` -- silently doing nothing after the user
        asked to publish is how a refusal gets mistaken for a success.
        """
        response = self._respond(report, await self._emit(report, request))
        if request.push:
            await self._push(request, response)
        return response

    # -- steps ------------------------------------------------------------

    async def _build(
        self,
        request: BuildImageRequest,
        dockerfile: Path,
        context_dir: Path,
    ) -> BuildResult:
        if not await self._builder.is_available():
            return BuildResult(
                success=False,
                tag=request.tag,
                error="Docker daemon is not reachable. Start Docker and retry, "
                "or use --validate-only to check the Dockerfile without building.",
            )
        options = BuildOptions(
            dockerfile_path=str(dockerfile),
            context_path=str(context_dir),
            tag=request.tag,
            build_args=dict(request.build_args),
            labels=await self._labels(request, context_dir),
            secrets=list(request.secrets),
            no_cache=request.no_cache,
            buildkit=request.buildkit,
            platform=request.platform,
            target=request.target,
        )
        return await self._builder.build(options)

    async def _labels(self, request: BuildImageRequest, context_dir: Path) -> dict[str, str]:
        """User labels plus provenance, without ever overwriting a label the
        user set explicitly."""
        metadata = await collect_build_metadata(str(context_dir), buildkit=request.buildkit)
        provenance = {
            "org.opencontainers.image.revision": metadata.git_sha or "unknown",
            "org.opencontainers.image.created": metadata.timestamp,
            "security.scanner": "dockerls",
            "security.scanner.version": metadata.dockerls_version,
        }
        labels = dict(provenance)
        labels.update(request.labels)
        return labels

    async def _scan(self, tag: str) -> list[ScanResult]:
        if self._scanner is None:
            logger.warning("No scanner available; skipping post-build scan")
            return []
        scanners = [self._scanner] + ([self._secondary] if self._secondary else [])
        results = await asyncio.gather(
            *(s.scan(tag) for s in scanners),
            return_exceptions=True,
        )
        scans: list[ScanResult] = []
        for scanner, result in zip(scanners, results, strict=True):
            if isinstance(result, BaseException):
                logger.error(f"{type(scanner).__name__} failed to scan {tag}: {result}")
                continue
            scans.append(result)
        return scans

    async def _sbom(self, tag: str) -> SbomInfo | None:
        generate = getattr(self._scanner, "generate_sbom", None)
        if generate is None:
            logger.info("Primary scanner cannot generate an SBOM; skipping")
            return None
        fmt = self._sbom_formats[0] if self._sbom_formats else "cyclonedx"
        trivy_fmt = "spdx-json" if fmt.startswith("spdx") else "cyclonedx"
        content = await generate(tag, fmt=trivy_fmt)
        if not content:
            return None
        return write_sbom(self._sbom_dir, tag, fmt, content)

    async def _emit(self, report: BuildReport, request: BuildImageRequest) -> list[str]:
        """Write every requested report format. A format that fails to write
        is logged and skipped -- losing the HTML copy must not discard the
        build's verdict."""
        if self._exporters is None:
            return []
        written: list[str] = []
        targets = _report_targets(request, self._report_dir, report.build_id)
        for fmt, path in targets:
            try:
                exporter = self._exporters.create(fmt)
                path.parent.mkdir(parents=True, exist_ok=True)
                exporter.export(report, path)
            except (OSError, ValueError) as e:
                logger.error(f"Could not write {fmt} report to {path}: {e}")
                continue
            written.append(str(path))
            if fmt == "json" and not report.report_file:
                report.report_file = str(path)
        return written

    async def _push(self, request: BuildImageRequest, response: BuildImageResponse) -> None:
        """Publish the image -- but only when the build actually passed.

        Pushing a FAILED build would defeat the gate entirely, so a
        `--push` on a failing build is refused and said out loud.
        """
        if not response.success:
            response.push_message = (
                "Not pushed: the build did not pass its security gate. "
                "Fix the findings above, or re-run with --force to accept them."
            )
            return
        ok, message = await self._builder.push(request.tag)
        response.pushed = ok
        response.push_message = message if ok else f"Push failed: {message}"
        if not ok:
            response.exit_code = EXIT_FAILED

    async def _docker_version(self) -> str:
        version = getattr(self._builder, "server_version", None)
        if version is None:
            return ""
        result = await version()
        return str(result)

    def _respond(self, report: BuildReport, written: list[str]) -> BuildImageResponse:
        exit_code = self._reports.exit_code(report)
        return BuildImageResponse(
            success=report.status != "FAILED",
            report=report,
            exit_code=exit_code,
            written_reports=written,
        )

    async def push_to_vault(self, response: BuildImageResponse, vault_path: str) -> None:
        """Record the build in the DevSecOps vault.

        Kept out of `execute` so a vault that is unreachable (a laptop
        without the notes directory mounted) cannot fail a build that
        otherwise passed.
        """
        if self._vault is None:
            response.vault_note = "Vault push requested but no vault root is configured"
            return
        try:
            path = await self._vault.push(response.report, vault_path)
        except (OSError, ValueError, VaultPushError) as e:
            logger.error(f"Vault push failed: {e}")
            response.vault_note = f"Vault push failed: {e}"
            return
        response.vault_note = path


def _report_targets(
    request: BuildImageRequest,
    report_dir: Path,
    build_id: str,
) -> list[tuple[str, Path]]:
    """Resolve which formats go to which files.

    An explicit `--report path.html` names both the format and the
    destination; `--report-format` without a path lands in the report
    directory under the build id, which is what CI wants.
    """
    targets: list[tuple[str, Path]] = []
    if request.report_path:
        path = Path(request.report_path)
        targets.append((_format_from_suffix(path), path))
    for fmt in request.report_formats:
        suffix = {"markdown": "md", "md": "md"}.get(fmt, fmt)
        candidate = report_dir / f"build_{build_id}.{suffix}"
        if any(existing == candidate for _, existing in targets):
            continue
        targets.append((fmt, candidate))
    return targets


def _format_from_suffix(path: Path) -> str:
    return {
        ".json": "json",
        ".html": "html",
        ".htm": "html",
        ".sarif": "sarif",
        ".md": "markdown",
        ".markdown": "markdown",
    }.get(path.suffix.lower(), "json")
