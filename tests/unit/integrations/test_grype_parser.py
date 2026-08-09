from unittest.mock import AsyncMock, patch

import pytest

from dockerls.domain.entities.scan_result import ScanStatus
from dockerls.integrations.grype.scanner import GrypeScanner
from tests.unit.integrations.conftest import stub_path


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
        assert result.is_verified is False

    @pytest.mark.asyncio
    async def test_timeout_is_timeout_status(self):
        scanner = GrypeScanner(timeout=1)
        proc = _FakeProc()
        with (
            patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
            patch("asyncio.wait_for", AsyncMock(side_effect=TimeoutError())),
        ):
            result = await scanner.scan("nginx:latest")
        assert result.status == ScanStatus.TIMEOUT

    @pytest.mark.asyncio
    async def test_successful_scan_has_ok_status(self):
        scanner = GrypeScanner()
        proc = _FakeProc(stdout=b'{"matches": []}', returncode=0)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            result = await scanner.scan("nginx:latest")
        assert result.status == ScanStatus.OK


class _FakeProcRC:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self._stdout, self._stderr, self.returncode = stdout, stderr, returncode

    async def communicate(self):
        return self._stdout, self._stderr


class TestGrypeDatabaseRefresh:
    """Grype checks its DB on every invocation unless told not to; that
    round trip per image was the dominant cross-validation cost."""

    @pytest.mark.asyncio
    async def test_refresh_db_runs_db_update(self):
        scanner = GrypeScanner()
        mock_exec = AsyncMock(return_value=_FakeProcRC(returncode=0))
        with patch("asyncio.create_subprocess_exec", mock_exec):
            assert await scanner.refresh_db() is True

        # argv[0] is the absolute path `shutil.which` resolved, not the bare
        # name: running the bare name would leave the choice of binary to
        # $PATH, which is the PATH hijacking this tool reports on others.
        assert list(mock_exec.call_args.args) == [stub_path("grype"), "db", "update"]

    @pytest.mark.asyncio
    async def test_scans_before_refresh_use_default_env(self):
        scanner = GrypeScanner()
        mock_exec = AsyncMock(return_value=_FakeProcRC(stdout=b'{"matches": []}'))
        with patch("asyncio.create_subprocess_exec", mock_exec):
            await scanner.scan("node:22-alpine")

        assert mock_exec.call_args.kwargs["env"] is None

    @pytest.mark.asyncio
    async def test_scans_after_refresh_disable_auto_update(self):
        scanner = GrypeScanner()
        mock_exec = AsyncMock(return_value=_FakeProcRC(stdout=b'{"matches": []}'))
        with patch("asyncio.create_subprocess_exec", mock_exec):
            await scanner.refresh_db()
            await scanner.scan("node:22-alpine")

        env = mock_exec.call_args.kwargs["env"]
        assert env["GRYPE_DB_AUTO_UPDATE"] == "false"
        assert env["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"

    @pytest.mark.asyncio
    async def test_failed_refresh_leaves_auto_update_on(self):
        """A failed pre-fetch must not leave scans running against a DB
        that was never updated with updates suppressed."""
        scanner = GrypeScanner()
        mock_exec = AsyncMock(return_value=_FakeProcRC(stderr=b"boom", returncode=1))
        with patch("asyncio.create_subprocess_exec", mock_exec):
            assert await scanner.refresh_db() is False
            await scanner.scan("node:22-alpine")

        assert mock_exec.call_args.kwargs["env"] is None
