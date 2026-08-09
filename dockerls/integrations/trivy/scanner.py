from __future__ import annotations

import asyncio
import json
import shutil
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from loguru import logger

from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.interfaces.scanner import ScannerInterface
from dockerls.integrations.trivy.cache_pool import TrivyCachePool, default_trivy_cache_dir
from dockerls.utils.executables import ExecutableNotFoundError, resolve_executable
from dockerls.utils.validation import sanitize_image_name

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.infrastructure.evidence import EvidenceStore


class TrivyScanner(ScannerInterface):
    def __init__(
        self,
        timeout: int = 300,
        skip_db_update: bool = False,
        cache_dir: Path | None = None,
        workers: int = 1,
        evidence: EvidenceStore | None = None,
    ):
        self._timeout = timeout
        self._skip_db_update = skip_db_update
        self._cache_pool = TrivyCachePool(cache_dir or default_trivy_cache_dir(), workers)
        self._evidence = evidence

    @property
    def cache_pool(self) -> TrivyCachePool:
        return self._cache_pool

    async def is_available(self) -> bool:
        return shutil.which("trivy") is not None

    def _cache_args(self, cache_dir: Path) -> list[str]:
        return ["--cache-dir", str(cache_dir)]

    async def generate_sbom(self, image_reference: str, fmt: str = "cyclonedx") -> str | None:
        """Generate an SBOM for `image_reference` using Trivy's built-in
        generators. `fmt` is one of "cyclonedx" or "spdx-json"."""
        if fmt not in ("cyclonedx", "spdx-json"):
            raise ValueError(f"Unsupported SBOM format: {fmt}")

        safe_ref = sanitize_image_name(image_reference)

        async with self._cache_pool.acquire() as cache_dir:
            try:
                cmd = [
                    resolve_executable("trivy"),
                    "image",
                    "--format",
                    fmt,
                    "--quiet",
                    *self._cache_args(cache_dir),
                ]
                if self._skip_db_update:
                    cmd.append("--skip-db-update")
                cmd.append(safe_ref)

                proc = await asyncio.create_subprocess_exec(  # noqa: S603 -- argv[0] resolvido
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self._timeout)
                if proc.returncode != 0 or not stdout:
                    logger.error(f"SBOM generation failed for {safe_ref}: {stderr.decode()[:300]}")
                    return None
                return stdout.decode()
            except (TimeoutError, OSError, ExecutableNotFoundError) as e:
                logger.error(f"SBOM generation failed for {safe_ref}: {e}")
                return None

    async def refresh_db(self) -> bool:
        """Download the vulnerability DB once, up front, then build the
        per-worker cache dir pool.

        Doing the download here (rather than letting the first scan trigger
        it) is what makes `--skip-db-update` safe for every subsequent scan,
        and it removes the single biggest source of cache lock contention.
        """
        base = self._cache_pool.base_dir
        try:
            proc = await asyncio.create_subprocess_exec(  # noqa: S603 -- argv[0] resolvido
                resolve_executable("trivy"),
                "image",
                "--download-db-only",
                "--quiet",
                *self._cache_args(base),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=self._timeout)
            if proc.returncode != 0:
                logger.warning(f"Trivy DB refresh failed: {stderr.decode()[:200]}")
                return False
        except (TimeoutError, OSError, ExecutableNotFoundError) as e:
            logger.warning(f"Trivy DB refresh failed: {e}")
            return False

        self._skip_db_update = True
        isolated = await self._cache_pool.prepare()
        logger.info(
            f"Trivy DB ready at {base}; "
            f"cache isolation {'enabled' if isolated else 'unavailable (scans serialized)'}"
        )
        return True

    async def close(self) -> None:
        await self._cache_pool.cleanup()

    async def scan(self, image_reference: str) -> ScanResult:
        safe_ref = sanitize_image_name(image_reference)
        logger.info(f"Scanning {safe_ref} with Trivy")
        timestamp = datetime.now(tz=UTC).isoformat()

        async with self._cache_pool.acquire() as cache_dir:
            try:
                cmd = [
                    resolve_executable("trivy"),
                    "image",
                    "--format",
                    "json",
                    "--severity",
                    "CRITICAL,HIGH,MEDIUM,LOW",
                    "--quiet",
                    *self._cache_args(cache_dir),
                ]
                if self._skip_db_update:
                    cmd.append("--skip-db-update")
                cmd.append(safe_ref)

                proc = await asyncio.create_subprocess_exec(  # noqa: S603 -- argv[0] resolvido
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self._timeout)

                if proc.returncode != 0:
                    # Trivy writes its own diagnostics to stderr; they are
                    # captured into the log file and folded into the run
                    # summary rather than dumped raw onto the terminal.
                    err = stderr.decode(errors="replace")[:500]
                    logger.error(f"Trivy returned code {proc.returncode} for {safe_ref}: {err}")
                    return ScanResult(
                        image_reference=safe_ref,
                        scanner="trivy",
                        scan_timestamp=timestamp,
                        status=ScanStatus.ERROR,
                        error_message=err,
                    )

                if not stdout:
                    return ScanResult(
                        image_reference=safe_ref,
                        scanner="trivy",
                        scan_timestamp=timestamp,
                        status=ScanStatus.ERROR,
                        error_message="Trivy produced no output",
                    )

                raw = stdout.decode()
                data = json.loads(raw)
                result = self._parse_results(safe_ref, data)
                if self._evidence is not None:
                    result.evidence_path = await self._evidence.record_scan(safe_ref, "trivy", raw)
                return result

            except TimeoutError:
                logger.error(f"Trivy scan timed out for {safe_ref}")
                return ScanResult(
                    image_reference=safe_ref,
                    scanner="trivy",
                    scan_timestamp=timestamp,
                    status=ScanStatus.TIMEOUT,
                    error_message=f"Scan exceeded {self._timeout}s timeout",
                )
            except (json.JSONDecodeError, OSError, ExecutableNotFoundError) as e:
                logger.error(f"Trivy scan failed for {safe_ref}: {e}")
                return ScanResult(
                    image_reference=safe_ref,
                    scanner="trivy",
                    scan_timestamp=timestamp,
                    status=ScanStatus.ERROR,
                    error_message=str(e),
                )

    def _parse_results(self, image_ref: str, data: dict[str, Any]) -> ScanResult:
        vulns: list[Vulnerability] = []
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                sev_str = v.get("Severity", "UNKNOWN").upper()
                try:
                    severity = Severity(sev_str)
                except ValueError:
                    severity = Severity.UNKNOWN

                vulns.append(
                    Vulnerability(
                        cve_id=v.get("VulnerabilityID", ""),
                        severity=severity,
                        cvss_score=self._extract_cvss(v),
                        package_name=v.get("PkgName", ""),
                        installed_version=v.get("InstalledVersion", ""),
                        fixed_version=v.get("FixedVersion", ""),
                        description=v.get("Title", "")[:200],
                        published_date=v.get("PublishedDate", ""),
                    )
                )

        return ScanResult(
            image_reference=image_ref,
            scanner="trivy",
            vulnerabilities=vulns,
            scan_timestamp=datetime.now(tz=UTC).isoformat(),
        )

    # Deterministic source preference: NVD is the canonical/authoritative
    # score; vendor-specific advisories come next; anything else is a
    # last-resort fallback so the same finding always yields the same score.
    _CVSS_SOURCE_PRIORITY = ("nvd", "redhat", "ghsa", "amazon", "photon", "oracle-oval")

    def _extract_cvss(self, vuln_data: dict[str, Any]) -> float:
        cvss = vuln_data.get("CVSS", {})
        for source in self._CVSS_SOURCE_PRIORITY:
            entry = cvss.get(source)
            score = self._score_from_entry(entry)
            if score is not None:
                return score
        for entry in cvss.values():
            score = self._score_from_entry(entry)
            if score is not None:
                return score
        return 0.0

    @staticmethod
    def _score_from_entry(entry: dict[str, Any] | None) -> float | None:
        if not entry:
            return None
        v4 = entry.get("V4Score")
        if v4 is not None:
            return float(v4)
        v3 = entry.get("V3Score")
        if v3 is not None:
            return float(v3)
        return None
