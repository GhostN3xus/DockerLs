from __future__ import annotations

import asyncio
import json
import os
import shutil
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from loguru import logger

from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.interfaces.scanner import ScannerInterface
from dockerls.utils.validation import sanitize_image_name

if TYPE_CHECKING:
    from dockerls.infrastructure.evidence import EvidenceStore


class GrypeScanner(ScannerInterface):
    def __init__(self, timeout: int = 300, evidence: EvidenceStore | None = None):
        self._timeout = timeout
        self._evidence = evidence
        self._skip_db_update = False

    async def is_available(self) -> bool:
        return shutil.which("grype") is not None

    def _scan_env(self) -> dict[str, str] | None:
        """Environment for a scan invocation.

        Left at None until the DB has been refreshed once, so a scanner used
        without `refresh_db()` still behaves exactly as before.
        """
        if not self._skip_db_update:
            return None
        env = os.environ.copy()
        env["GRYPE_DB_AUTO_UPDATE"] = "false"
        env["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"
        return env

    async def refresh_db(self) -> bool:
        """Update the vulnerability DB once, up front.

        Grype otherwise checks its DB freshness on *every* invocation, which
        is a network round trip per scan -- the dominant cost when
        cross-validating several images. After this succeeds, scans run with
        GRYPE_DB_AUTO_UPDATE=false so they go straight to matching.
        """
        try:
            proc = await asyncio.create_subprocess_exec(  # noqa: S603
                "grype",
                "db",
                "update",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=self._timeout)
            if proc.returncode != 0:
                logger.warning(f"Grype DB refresh failed: {stderr.decode()[:200]}")
                return False
        except (TimeoutError, OSError) as e:
            logger.warning(f"Grype DB refresh failed: {e}")
            return False

        self._skip_db_update = True
        logger.info("Grype DB ready; per-scan auto-update disabled")
        return True

    async def scan(self, image_reference: str) -> ScanResult:
        safe_ref = sanitize_image_name(image_reference)
        logger.info(f"Scanning {safe_ref} with Grype")
        timestamp = datetime.now(tz=UTC).isoformat()

        try:
            proc = await asyncio.create_subprocess_exec(  # noqa: S603
                "grype",
                safe_ref,
                "-o",
                "json",
                "--quiet",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._scan_env(),
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self._timeout)

            if proc.returncode != 0:
                err = stderr.decode(errors="replace")[:500]
                logger.error(f"Grype returned code {proc.returncode} for {safe_ref}: {err}")
                return ScanResult(
                    image_reference=safe_ref,
                    scanner="grype",
                    scan_timestamp=timestamp,
                    status=ScanStatus.ERROR,
                    error_message=err,
                )

            if not stdout:
                return ScanResult(
                    image_reference=safe_ref,
                    scanner="grype",
                    scan_timestamp=timestamp,
                    status=ScanStatus.ERROR,
                    error_message="Grype produced no output",
                )

            raw = stdout.decode()
            data = json.loads(raw)
            result = self._parse_results(safe_ref, data)
            if self._evidence is not None:
                result.evidence_path = await self._evidence.record_scan(safe_ref, "grype", raw)
            return result

        except TimeoutError:
            logger.error(f"Grype scan timed out for {safe_ref}")
            return ScanResult(
                image_reference=safe_ref,
                scanner="grype",
                scan_timestamp=timestamp,
                status=ScanStatus.TIMEOUT,
                error_message=f"Scan exceeded {self._timeout}s timeout",
            )
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Grype scan failed for {safe_ref}: {e}")
            return ScanResult(
                image_reference=safe_ref,
                scanner="grype",
                scan_timestamp=timestamp,
                status=ScanStatus.ERROR,
                error_message=str(e),
            )

    def _parse_results(self, image_ref: str, data: dict[str, Any]) -> ScanResult:
        vulns: list[Vulnerability] = []
        for match in data.get("matches", []):
            vd = match.get("vulnerability", {})
            sev_str = vd.get("severity", "Unknown").upper()
            if sev_str == "NEGLIGIBLE":
                sev_str = "LOW"
            try:
                severity = Severity(sev_str)
            except ValueError:
                severity = Severity.UNKNOWN

            artifact = match.get("artifact", {})
            fixed_versions = vd.get("fix", {}).get("versions", [])
            fixed_version = fixed_versions[0] if fixed_versions else ""

            cvss_score = self._extract_cvss(vd.get("cvss", []))

            vulns.append(
                Vulnerability(
                    cve_id=vd.get("id", ""),
                    severity=severity,
                    cvss_score=cvss_score,
                    package_name=artifact.get("name", ""),
                    installed_version=artifact.get("version", ""),
                    fixed_version=fixed_version,
                    description=vd.get("description", "")[:200],
                )
            )

        return ScanResult(
            image_reference=image_ref,
            scanner="grype",
            vulnerabilities=vulns,
            scan_timestamp=datetime.now(tz=UTC).isoformat(),
        )

    @staticmethod
    def _extract_cvss(entries: list[dict[str, Any]]) -> float:
        """Deterministic CVSS selection: NVD source > any other vendor
        source > first available, instead of an arbitrary max() across
        differently-scored advisories."""
        if not entries:
            return 0.0

        def base_score(entry: dict[str, Any]) -> float:
            return float(entry.get("metrics", {}).get("baseScore", 0.0))

        for entry in entries:
            if "nvd" in str(entry.get("source", "")).lower():
                return base_score(entry)

        return base_score(entries[0])
