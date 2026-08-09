from unittest.mock import AsyncMock, patch

import pytest

from dockerls.domain.entities.scan_result import ScanStatus
from dockerls.integrations.trivy.scanner import TrivyScanner


class TestTrivyParser:
    def test_parse_results(self):
        scanner = TrivyScanner()
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "Severity": "HIGH",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.1",
                            "FixedVersion": "3.0.2",
                            "Title": "Buffer overflow",
                            "CVSS": {"nvd": {"V3Score": 7.5}},
                        },
                        {
                            "VulnerabilityID": "CVE-2024-0002",
                            "Severity": "CRITICAL",
                            "PkgName": "curl",
                            "InstalledVersion": "7.88.0",
                            "FixedVersion": "",
                            "Title": "RCE in curl",
                        },
                    ]
                }
            ]
        }
        result = scanner._parse_results("node:22-alpine", data)
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.fixable_count == 1
        assert result.vulnerabilities[0].cvss_score == 7.5

    def test_parse_empty(self):
        scanner = TrivyScanner()
        result = scanner._parse_results("node:latest", {"Results": []})
        assert result.total_count == 0


class _FakeProc:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode

    async def communicate(self):
        return self._stdout, self._stderr


class TestTrivyScanErrorPaths:
    @pytest.mark.asyncio
    async def test_nonzero_exit_is_error_status(self):
        scanner = TrivyScanner()
        proc = _FakeProc(stdout=b"", stderr=b"unknown flag", returncode=1)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            result = await scanner.scan("node:22-alpine")
        assert result.status == ScanStatus.ERROR
        assert result.is_verified is False

    @pytest.mark.asyncio
    async def test_timeout_is_timeout_status(self):
        scanner = TrivyScanner(timeout=1)
        proc = _FakeProc()
        with (
            patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)),
            patch("asyncio.wait_for", AsyncMock(side_effect=TimeoutError())),
        ):
            result = await scanner.scan("node:22-alpine")
        assert result.status == ScanStatus.TIMEOUT
        assert result.is_verified is False

    @pytest.mark.asyncio
    async def test_malformed_json_is_error_status(self):
        scanner = TrivyScanner()
        proc = _FakeProc(stdout=b"not json", returncode=0)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            result = await scanner.scan("node:22-alpine")
        assert result.status == ScanStatus.ERROR

    @pytest.mark.asyncio
    async def test_successful_scan_has_ok_status(self):
        scanner = TrivyScanner()
        proc = _FakeProc(stdout=b'{"Results": []}', returncode=0)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            result = await scanner.scan("node:22-alpine")
        assert result.status == ScanStatus.OK
        assert result.is_verified is True

    @pytest.mark.asyncio
    async def test_skip_db_update_flag_passed(self):
        scanner = TrivyScanner(skip_db_update=True)
        proc = _FakeProc(stdout=b'{"Results": []}', returncode=0)
        mock_exec = AsyncMock(return_value=proc)
        with patch("asyncio.create_subprocess_exec", mock_exec):
            await scanner.scan("node:22-alpine")
        args = mock_exec.call_args.args
        assert "--skip-db-update" in args

    @pytest.mark.asyncio
    async def test_generate_sbom_returns_output(self):
        scanner = TrivyScanner()
        proc = _FakeProc(stdout=b'{"bomFormat": "CycloneDX"}', returncode=0)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            sbom = await scanner.generate_sbom("node:22-alpine", fmt="cyclonedx")
        assert sbom is not None
        assert "CycloneDX" in sbom

    @pytest.mark.asyncio
    async def test_generate_sbom_invalid_format_raises(self):
        scanner = TrivyScanner()
        with pytest.raises(ValueError):
            await scanner.generate_sbom("node:22-alpine", fmt="bogus")

    @pytest.mark.asyncio
    async def test_generate_sbom_failure_returns_none(self):
        scanner = TrivyScanner()
        proc = _FakeProc(stdout=b"", stderr=b"error", returncode=1)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            sbom = await scanner.generate_sbom("node:22-alpine")
        assert sbom is None

    @pytest.mark.asyncio
    async def test_refresh_db_enables_skip_flag(self):
        scanner = TrivyScanner()
        proc = _FakeProc(stdout=b"", returncode=0)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            ok = await scanner.refresh_db()
        assert ok is True
        assert scanner._skip_db_update is True


class TestTrivyErrorPathsAndScoring:
    """Caminhos de erro e de pontuação: um scanner que falha em silêncio, ou
    que pontua o mesmo achado de formas diferentes, corrompe o veredito que o
    pipeline confia."""

    @pytest.mark.asyncio
    async def test_empty_output_is_an_error_not_a_clean_image(self):
        """Trivy sair com 0 e não escrever nada não é "zero vulnerabilidades":
        é um scan que não aconteceu, e precisa ser marcado como tal."""
        scanner = TrivyScanner()
        proc = _FakeProc(stdout=b"", returncode=0)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            result = await scanner.scan("node:22-alpine")

        assert result.status == ScanStatus.ERROR
        assert result.total_count == 0
        assert "no output" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_missing_trivy_binary_is_reported_as_an_error(self):
        scanner = TrivyScanner()
        with patch("shutil.which", lambda name: None):
            result = await scanner.scan("node:22-alpine")

        assert result.status == ScanStatus.ERROR
        assert "trivy" in result.error_message

    @pytest.mark.asyncio
    async def test_refresh_db_failure_leaves_skip_flag_off(self):
        """Um pré-download falho não pode deixar os scans seguintes rodando
        com `--skip-db-update` contra uma base que nunca foi atualizada."""
        scanner = TrivyScanner()
        proc = _FakeProc(stderr=b"boom", returncode=1)
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            assert await scanner.refresh_db() is False

        assert scanner._skip_db_update is False

    @pytest.mark.asyncio
    async def test_refresh_db_survives_a_missing_binary(self):
        scanner = TrivyScanner()
        with patch("shutil.which", lambda name: None):
            assert await scanner.refresh_db() is False

    @pytest.mark.asyncio
    async def test_sbom_generation_survives_a_missing_binary(self):
        scanner = TrivyScanner()
        with patch("shutil.which", lambda name: None):
            assert await scanner.generate_sbom("node:22-alpine") is None

    @pytest.mark.asyncio
    async def test_sbom_generation_reports_a_timeout_as_none(self):
        scanner = TrivyScanner(timeout=1)
        with patch("asyncio.create_subprocess_exec", AsyncMock(side_effect=TimeoutError)):
            assert await scanner.generate_sbom("node:22-alpine") is None

    @pytest.mark.asyncio
    async def test_is_available_follows_the_path_lookup(self):
        scanner = TrivyScanner()
        with patch("shutil.which", lambda name: None):
            assert await scanner.is_available() is False
        with patch("shutil.which", lambda name: "/usr/bin/trivy"):
            assert await scanner.is_available() is True

    def test_unknown_severity_string_does_not_drop_the_finding(self):
        """Uma severidade que a Trivy invente não pode sumir com o achado."""
        scanner = TrivyScanner()
        data = {
            "Results": [
                {"Vulnerabilities": [{"VulnerabilityID": "CVE-2026-1", "Severity": "BOGUS"}]}
            ]
        }
        result = scanner._parse_results("node:22-alpine", data)

        assert result.total_count == 1
        assert result.vulnerabilities[0].cve_id == "CVE-2026-1"

    def test_cvss_prefers_nvd_over_a_vendor_score(self):
        """A preferência de fonte é o que torna o score determinístico: sem
        ela o mesmo achado pontua diferente conforme a ordem do dicionário."""
        scanner = TrivyScanner()
        vuln = {"CVSS": {"redhat": {"V3Score": 5.0}, "nvd": {"V3Score": 9.8}}}
        assert scanner._extract_cvss(vuln) == 9.8

    def test_cvss_prefers_v4_over_v3_within_a_source(self):
        scanner = TrivyScanner()
        assert scanner._extract_cvss({"CVSS": {"nvd": {"V3Score": 7.5, "V4Score": 8.2}}}) == 8.2

    def test_cvss_falls_back_to_an_unranked_source(self):
        scanner = TrivyScanner()
        assert scanner._extract_cvss({"CVSS": {"vendorx": {"V3Score": 6.1}}}) == 6.1

    def test_cvss_without_any_score_is_zero(self):
        scanner = TrivyScanner()
        assert scanner._extract_cvss({"CVSS": {"nvd": {}}}) == 0.0
        assert scanner._extract_cvss({}) == 0.0
