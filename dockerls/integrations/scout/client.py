from __future__ import annotations

import asyncio
import json
import shutil
from datetime import datetime, timezone

from loguru import logger

from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.utils.validation import sanitize_image_name


class DockerScoutClient:
    async def is_available(self) -> bool:
        return shutil.which("docker") is not None

    async def get_cves(self, image_reference: str) -> ScanResult:
        safe_ref = sanitize_image_name(image_reference)
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "scout", "cves", safe_ref, "--format", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)

            if not stdout:
                return ScanResult(
                    image_reference=safe_ref, scanner="docker-scout",
                    scan_timestamp=datetime.now(tz=timezone.utc).isoformat(),
                )

            data = json.loads(stdout.decode())
            vulns: list[Vulnerability] = []
            for vd in data.get("vulnerabilities", []):
                sev_str = vd.get("severity", "UNKNOWN").upper()
                try:
                    severity = Severity(sev_str)
                except ValueError:
                    severity = Severity.UNKNOWN
                vulns.append(Vulnerability(
                    cve_id=vd.get("id", ""),
                    severity=severity,
                    cvss_score=vd.get("cvssScore", 0.0),
                    package_name=vd.get("package", ""),
                    installed_version=vd.get("version", ""),
                    fixed_version=vd.get("fixedVersion", ""),
                ))

            return ScanResult(
                image_reference=safe_ref, scanner="docker-scout",
                vulnerabilities=vulns,
                scan_timestamp=datetime.now(tz=timezone.utc).isoformat(),
            )
        except Exception as e:
            logger.debug(f"Docker Scout not available: {e}")
            return ScanResult(
                image_reference=safe_ref, scanner="docker-scout",
                scan_timestamp=datetime.now(tz=timezone.utc).isoformat(),
            )
