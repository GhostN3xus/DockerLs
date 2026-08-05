from __future__ import annotations

import asyncio
import json
import shutil
from datetime import datetime, timezone

from loguru import logger

from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.interfaces.scanner import ScannerInterface
from dockerls.utils.validation import sanitize_image_name


class GrypeScanner(ScannerInterface):
    def __init__(self, timeout: int = 300):
        self._timeout = timeout

    async def is_available(self) -> bool:
        return shutil.which("grype") is not None

    async def scan(self, image_reference: str) -> ScanResult:
        safe_ref = sanitize_image_name(image_reference)
        logger.info(f"Scanning {safe_ref} with Grype")

        try:
            proc = await asyncio.create_subprocess_exec(
                "grype", safe_ref, "-o", "json", "--quiet",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._timeout
            )

            if not stdout:
                return ScanResult(
                    image_reference=safe_ref, scanner="grype",
                    scan_timestamp=datetime.now(tz=timezone.utc).isoformat(),
                )

            data = json.loads(stdout.decode())
            return self._parse_results(safe_ref, data)

        except (asyncio.TimeoutError, json.JSONDecodeError, OSError) as e:
            logger.error(f"Grype scan failed for {safe_ref}: {e}")
            return ScanResult(
                image_reference=safe_ref, scanner="grype",
                scan_timestamp=datetime.now(tz=timezone.utc).isoformat(),
            )

    def _parse_results(self, image_ref: str, data: dict) -> ScanResult:
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

            cvss_score = 0.0
            for entry in vd.get("cvss", []):
                score = entry.get("metrics", {}).get("baseScore", 0.0)
                if score > cvss_score:
                    cvss_score = score

            vulns.append(Vulnerability(
                cve_id=vd.get("id", ""),
                severity=severity,
                cvss_score=cvss_score,
                package_name=artifact.get("name", ""),
                installed_version=artifact.get("version", ""),
                fixed_version=fixed_version,
                description=vd.get("description", "")[:200],
            ))

        return ScanResult(
            image_reference=image_ref, scanner="grype",
            vulnerabilities=vulns,
            scan_timestamp=datetime.now(tz=timezone.utc).isoformat(),
        )
