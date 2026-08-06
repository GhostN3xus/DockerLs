import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from dockerls.domain.entities.scan_result import ScanStatus
from dockerls.integrations.grype.scanner import GrypeScanner


class TestGrypeParser:
    def test_parse_results(self):
        scanner = GrypeScanner()
        data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-1111",
                        "severity": "High",
                        "fix": {"versions": ["2.0.0"]},
                        "cvss": [{"metrics": {"baseScore": 8.1}}],
                    },
                    "artifact": {
                        "name": "libxml2",
                        "version": "1.9.0",
                    },
                },
                {
                    "vulnerability": {
                        "id": "CVE-2024-2222",
                        "severity": "Negligible",
                        "fix": {"versions": []},
                        "cvss": [],
                    },
                    "artifact": {"name": "zlib", "version": "1.2.11"},
                },
            ]
        }
        result = scanner._parse_results("python:3.12", data)
        assert result.high_count == 1
        assert result.low_count == 1
        assert result.fixable_count == 1
        assert result.vulnerabilities[0].cvss_score == 8.1

    def test_parse_empty(self):
        scanner = GrypeScanner()
        result = scanner._parse_results("nginx:latest", {"matches": []})
        assert result.total_count == 0


class _FakeProc:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self):
        return self._stdout, self._stderr


class TestGrypeScanErrorPaths:
    @pytest.mark.asyncio
    async def test_nonzero_exit_is_error_status(self):
        scanner = GrypeScanner()
        proc = _FakeProc(stdout=b"", stderr=b"boom", returncode=1)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            result = await scanner.scan("nginx:latest")
        assert result.status == ScanStatus.ERROR
        assert result.is_usable is False

    @pytest.mark.asyncio
    async def test_timeout_is_timeout_status(self):
        scanner = GrypeScanner(timeout=1)
        proc = _FakeProc()
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)), \
             patch("asyncio.wait_for", AsyncMock(side_effect=asyncio.TimeoutError())):
            result = await scanner.scan("nginx:latest")
        assert result.status == ScanStatus.TIMEOUT

    @pytest.mark.asyncio
    async def test_successful_scan_has_ok_status(self):
        scanner = GrypeScanner()
        proc = _FakeProc(stdout=b'{"matches": []}', returncode=0)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            result = await scanner.scan("nginx:latest")
        assert result.status == ScanStatus.OK
