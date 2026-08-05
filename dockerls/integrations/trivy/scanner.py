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


class TrivyScanner(ScannerInterface):
    def __init__(self, timeout: int = 300):
        self._timeout = timeout

    async def is_available(self) -> bool:
        return shutil.which("trivy") is not None

    async def scan(self, image_reference: str) -> ScanResult:
        safe_ref = sanitize_image_name(image_reference)
        logger.info(f"Scanning {safe_ref} with Trivy")

        try:
            proc = await asyncio.create_subprocess_exec(
                "trivy", "image", "--format", "json",
                "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
                "--quiet", safe_ref,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._timeout
            )

            if proc.returncode != 0:
                logger.warning(
                    f"Trivy returned code {proc.returncode}: "
                    f"{stderr.decode()[:200]}"
                )

            if not stdout:
                return ScanResult(
                    image_reference=safe_ref, scanner="trivy",
                    scan_timestamp=datetime.now(tz=timezone.utc).isoformat(),
                )

            data = json.loads(stdout.decode())
            return self._parse_results(safe_ref, data)

        except asyncio.TimeoutError:
            logger.error(f"Trivy scan timed out for {safe_ref}")
            return ScanResult(
                image_reference=safe_ref, scanner="trivy",
                scan_timestamp=datetime.now(tz=timezone.utc).isoformat(),
            )
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Trivy scan failed for {safe_ref}: {e}")
            return ScanResult(
                image_reference=safe_ref, scanner="trivy",
                scan_timestamp=datetime.now(tz=timezone.utc).isoformat(),
            )

    def _parse_results(self, image_ref: str, data: dict) -> ScanResult:
        vulns: list[Vulnerability] = []
        for result in data.get("Results", []):
            for v in result.get("Vulnerabilities", []):
                sev_str = v.get("Severity", "UNKNOWN").upper()
                try:
                    severity = Severity(sev_str)
                except ValueError:
                    severity = Severity.UNKNOWN

                vulns.append(Vulnerability(
                    cve_id=v.get("VulnerabilityID", ""),
                    severity=severity,
                    cvss_score=self._extract_cvss(v),
                    package_name=v.get("PkgName", ""),
                    installed_version=v.get("InstalledVersion", ""),
                    fixed_version=v.get("FixedVersion", ""),
                    description=v.get("Title", "")[:200],
                    published_date=v.get("PublishedDate", ""),
                ))

        return ScanResult(
            image_reference=image_ref, scanner="trivy",
            vulnerabilities=vulns,
            scan_timestamp=datetime.now(tz=timezone.utc).isoformat(),
        )

    def _extract_cvss(self, vuln_data: dict) -> float:
        cvss = vuln_data.get("CVSS", {})
        for source in cvss.values():
            v3 = source.get("V3Score")
            if v3 is not None:
                return float(v3)
        return 0.0
