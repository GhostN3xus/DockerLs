"""Testes para o BuildImageUseCase.

Os fixtures mockam `DockerfileValidatorInterface`, que é o que o caso de uso
realmente depende. Antes eles devolviam de `validate()` um objeto no formato
de `AnalyzeDockerfileResponse`; como `BuildImageUseCase` instancia um
`AnalyzeDockerfileUseCase` internamente, esse retorno era envelopado numa
segunda camada e `response.validation.errors` caía num `MagicMock`, que nunca
é igual a `0` -- então todo cenário "sem erros" chegava como reprovado.
"""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from dockerls.application.use_cases.analyze_dockerfile import AnalyzeDockerfileResponse
from dockerls.application.use_cases.build_image import (
    BuildImageRequest,
    BuildImageUseCase,
    BuildOptions,
    BuildResult,
    ScanResult,
)
from dockerls.domain.entities.dockerfile_analysis import (
    DockerfileAnalysis,
    DockerfileInfo,
    DockerfileValidationResult,
    HardeningRule,
    SeverityLevel,
    ValidationCheck,
    ValidationStatus,
)
from dockerls.domain.interfaces.dockerfile_validator import (
    DockerfileValidatorInterface,
    HardeningTemplateProvider,
)
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY
from dockerls.infrastructure.dockerfile_validator import HardeningTemplates
from dockerls.utils.executables import ExecutableNotFoundError


def _validation(
    passed: int = 10,
    warnings: int = 0,
    errors: int = 0,
    checks: list[ValidationCheck] | None = None,
) -> DockerfileValidationResult:
    return DockerfileValidationResult(
        dockerfile_path="Dockerfile",
        passed=passed,
        warnings=warnings,
        errors=errors,
        checks=checks or [],
    )


def _analysis(validation: DockerfileValidationResult, score: int = 90) -> DockerfileAnalysis:
    return DockerfileAnalysis(
        info=DockerfileInfo(),
        validation=validation,
        security_score=score,
        security_tier="A" if score >= 90 else "C",
    )


class TestBuildImageUseCase:
    """Testes para o caso de uso de build de imagem."""

    @pytest.fixture
    def context(self, tmp_path):
        """Diretório de contexto com um Dockerfile real.

        O caso de uso resolve `<context>/Dockerfile` no disco antes de
        chamar o validador, então o arquivo precisa existir mesmo com o
        validador mockado.
        """
        (tmp_path / "Dockerfile").write_text("FROM node:22-alpine\nUSER node\n")
        return tmp_path

    @pytest.fixture
    def validator(self):
        """Mock da interface do validador, com os tipos que ela devolve."""
        mock = MagicMock(spec=DockerfileValidatorInterface)
        validation = _validation()
        mock.validate.return_value = validation
        mock.analyze.return_value = _analysis(validation)
        mock.suggest_hardening.return_value = []
        return mock

    @pytest.fixture
    def template_provider(self):
        return MagicMock(spec=HardeningTemplateProvider)

    @pytest.fixture
    def use_case(self, validator, template_provider):
        return BuildImageUseCase(validator, template_provider)

    def test_build_valid_dockerfile_succeeds(self, use_case, context):
        """Dockerfile sem erros passa na validação com exit 0."""
        response = use_case.execute(
            BuildImageRequest(context_path=str(context), tag="test:latest", validate_only=True)
        )

        assert response.success is True
        assert response.exit_code == EXIT_OK
        assert response.error is None

    def test_validate_only_response_carries_the_checks(self, use_case, validator, context):
        """A resposta precisa levar o resultado da validação inteiro.

        É o defeito que fazia a CLI imprimir `None`: sem `validation` e sem
        `report`, não havia o que renderizar.
        """
        validation = _validation(
            passed=1,
            warnings=1,
            checks=[
                ValidationCheck(
                    check="no_latest_tag",
                    status=ValidationStatus.WARN,
                    message="Base image uses :latest tag",
                ),
            ],
        )
        validator.validate.return_value = validation
        validator.analyze.return_value = _analysis(validation, score=80)

        response = use_case.execute(
            BuildImageRequest(context_path=str(context), tag="test:latest", validate_only=True)
        )

        assert response.validation is validation
        assert [c.check for c in response.validation.checks] == ["no_latest_tag"]
        assert response.report is not None
        assert response.report.validation["checks"][0]["check"] == "no_latest_tag"
        assert response.report.security_score == 80

    def test_validation_fails_on_secrets_in_env(self, use_case, validator, context):
        """Deve rejeitar secrets em ENV, dizendo qual regra falhou."""
        validation = _validation(
            passed=8,
            errors=2,
            checks=[
                ValidationCheck(
                    check="secrets_not_in_env",
                    status=ValidationStatus.FAIL,
                    message="ENV DOCKER_TOKEN detected",
                    line=15,
                ),
                ValidationCheck(
                    check="non_root_user",
                    status=ValidationStatus.FAIL,
                    message="No USER directive found",
                ),
            ],
        )
        validator.validate.return_value = validation
        validator.analyze.return_value = _analysis(validation, score=40)

        response = use_case.execute(
            BuildImageRequest(context_path=str(context), tag="test:latest", validate_only=True)
        )

        assert response.success is False
        # Política violada, não erro de execução: a validação rodou bem.
        assert response.exit_code == EXIT_POLICY
        assert "validation failed" in response.error.lower()
        # O resumo precisa nomear as regras -- é a única coisa que um log de
        # CI guarda quando ninguém está olhando o terminal.
        assert "secrets_not_in_env" in response.error
        assert "line 15" in response.error
        assert "non_root_user" in response.error

    def test_validation_warns_on_latest_tag(self, use_case, validator, context):
        """Warnings não reprovam o build."""
        validation = _validation(
            passed=9,
            warnings=1,
            checks=[
                ValidationCheck(
                    check="no_latest_tag",
                    status=ValidationStatus.WARN,
                    message="Base image uses :latest tag",
                ),
            ],
        )
        validator.validate.return_value = validation
        validator.analyze.return_value = _analysis(validation, score=85)

        response = use_case.execute(
            BuildImageRequest(context_path=str(context), tag="test:latest", validate_only=True)
        )

        assert response.success is True
        assert response.exit_code == EXIT_OK

    def test_missing_dockerfile_is_an_execution_error(self, use_case, tmp_path):
        """Dockerfile inexistente é exit 1, não 2: nada foi medido."""
        response = use_case.execute(
            BuildImageRequest(context_path=str(tmp_path), tag="test:latest", validate_only=True)
        )

        assert response.success is False
        assert response.exit_code == EXIT_ERROR
        assert "not found" in response.error.lower()

    def test_validation_errors_block_the_build(self, use_case, validator, context):
        """Um Dockerfile reprovado não chega a ser construído.

        O portão antigo era `if not validation_result`, e um objeto é sempre
        verdadeiro -- então nunca disparava.
        """
        validation = _validation(passed=1, errors=1)
        validator.validate.return_value = validation
        validator.analyze.return_value = _analysis(validation, score=20)

        with patch.object(use_case, "_build_image") as mock_build:
            response = use_case.execute(
                BuildImageRequest(context_path=str(context), tag="test:latest", scan=False)
            )

        mock_build.assert_not_called()
        assert response.success is False
        assert response.exit_code == EXIT_POLICY

    def test_force_builds_despite_validation_errors(self, use_case, validator, context):
        """`--force` é a saída documentada para construir mesmo reprovado."""
        validation = _validation(passed=1, errors=1)
        validator.validate.return_value = validation
        validator.analyze.return_value = _analysis(validation, score=20)

        with patch.object(use_case, "_build_image") as mock_build:
            mock_build.return_value = BuildResult(success=True, image_tag="test:latest")
            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(context), tag="test:latest", scan=False, force=True
                )
            )

        mock_build.assert_called_once()
        assert response.success is True
        assert response.exit_code == EXIT_OK

    def test_suggests_hardening_rules(self, use_case, validator, context):
        """Deve sugerir melhorias de hardening."""
        validator.suggest_hardening.return_value = [
            HardeningRule(
                priority=SeverityLevel.HIGH,
                title="Add non-root user",
                description="Container should run as non-root",
                current_state="Running as root",
                suggested_fix="USER appuser",
                reason="Security best practice",
            ),
        ]

        response = use_case.execute(
            BuildImageRequest(context_path=str(context), tag="test:latest", suggest_only=True)
        )

        assert response.success is True
        assert response.exit_code == EXIT_OK
        assert [r.title for r in response.recommendations] == ["Add non-root user"]

    def test_validate_only_does_not_write_hardened_dockerfile(self, validator, context):
        """`--validate-only` é dry-run: não pode escrever em disco.

        Com um provider real, gerar o arquivo seria efeito colateral de um
        comando que o usuário pediu para não construir nada.
        """
        use_case = BuildImageUseCase(validator, HardeningTemplates())

        response = use_case.execute(
            BuildImageRequest(
                context_path=str(context),
                tag="test:latest",
                hardened=True,
                base_template="node",
                validate_only=True,
            )
        )

        assert response.success is True
        assert not (context / "Dockerfile.hardened").exists()

    def test_hardened_build_writes_dockerfile(self, validator, context):
        """Sem `--validate-only`, o template hardened vai para o disco.

        A escrita acontece na infraestrutura, por trás de
        `generate_hardened_dockerfile()`, e não no caso de uso.
        """
        use_case = BuildImageUseCase(validator, HardeningTemplates())

        with patch.object(use_case, "_build_image") as mock_build:
            mock_build.return_value = BuildResult(success=True, image_tag="test:latest")
            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    hardened=True,
                    base_template="node",
                    scan=False,
                )
            )

        hardened_path = context / "Dockerfile.hardened"
        assert response.success is True
        assert hardened_path.exists()
        assert "FROM" in hardened_path.read_text()
        # E é esse arquivo que o build recebe, não o Dockerfile original.
        assert mock_build.call_args.kwargs["dockerfile_path"] == str(hardened_path)

    def test_ci_mode_returns_json_only(self, use_case, context):
        """CI mode não muda o veredito, só a formatação (feita na CLI)."""
        response = use_case.execute(
            BuildImageRequest(
                context_path=str(context),
                tag="test:latest",
                ci_mode=True,
                validate_only=True,
            )
        )

        assert response.success is True
        assert response.exit_code == EXIT_OK
        assert response.report is not None

    def test_fail_on_critical_reproofs_build(self, use_case, context):
        """`--fail-on critical` é violação de política: exit 2."""
        with (
            patch.object(use_case, "_scan_image") as mock_scan,
            patch.object(use_case, "_build_image") as mock_build,
        ):
            mock_scan.return_value = ScanResult(critical=2, high=0, medium=5, low=10)
            mock_build.return_value = BuildResult(
                success=True, image_tag="test:latest", image_sha256="sha256:abc123"
            )

            response = use_case.execute(
                BuildImageRequest(
                    context_path=str(context),
                    tag="test:latest",
                    scan=True,
                    fail_on="critical",
                )
            )

        assert response.success is False
        assert response.exit_code == EXIT_POLICY
        assert "Vulnerabilities exceed threshold" in response.error

    def test_docker_build_failure_is_an_execution_error(self, use_case, context):
        """Erro do `docker build` é exit 1: infraestrutura, não política."""
        with patch.object(use_case, "_build_image") as mock_build:
            mock_build.return_value = BuildResult(
                success=False, error_message="Build failed: no such file"
            )
            response = use_case.execute(
                BuildImageRequest(context_path=str(context), tag="test:latest", scan=False)
            )

        assert response.success is False
        assert response.exit_code == EXIT_ERROR

    def test_security_score_calculation(self, use_case):
        """Testa cálculo do security score."""
        analyze_response = AnalyzeDockerfileResponse(
            success=True,
            validation=_validation(passed=8, warnings=2, errors=0),
        )
        scan_result = ScanResult(critical=0, high=1, medium=3, low=5)

        score = use_case._calculate_security_score(analyze_response, scan_result)

        # 100 - (0*10) - (2*3) - (0*15) - (1*10) - (3*3) - (5*1) = 70
        assert score == 70

    def test_security_tier_calculation(self, use_case):
        """Testa cálculo do security tier."""
        assert use_case._calculate_security_tier(95) == "A"
        assert use_case._calculate_security_tier(80) == "B"
        assert use_case._calculate_security_tier(65) == "C"
        assert use_case._calculate_security_tier(50) == "D"
        assert use_case._calculate_security_tier(30) == "F"

    def test_report_generation(self, use_case):
        """Deve gerar relatório JSON válido."""
        validation = _validation(passed=10)
        analyze_response = AnalyzeDockerfileResponse(
            success=True,
            validation=validation,
            analysis=_analysis(validation),
            suggestions=[
                HardeningRule(
                    priority=SeverityLevel.MEDIUM,
                    title="Add HEALTHCHECK",
                    description="No health check",
                    current_state="absent",
                    suggested_fix="HEALTHCHECK ...",
                    reason="orchestrators need it",
                ),
            ],
        )

        report = use_case._generate_report(
            validation=analyze_response,
            build=BuildResult(
                success=True,
                image_tag="test:latest",
                image_sha256="sha256:abc123",
                build_time_seconds=45.0,
            ),
            scan=ScanResult(critical=0, high=0, medium=2, low=5),
            image_tag="test:latest",
            dockerfile_path="Dockerfile",
        )

        assert report.build_id is not None
        assert report.timestamp is not None
        assert report.image == "test:latest"
        assert report.security_score > 0
        assert report.security_tier in ["A", "B", "C", "D", "F"]
        assert isinstance(report.validation, dict)
        assert report.scan_results is not None
        # As recomendações vêm das sugestões de hardening; ler
        # `analysis.recommendations` era acesso a um atributo inexistente.
        assert report.recommendations[0]["title"] == "Add HEALTHCHECK"

    def test_git_sha_extraction(self, use_case):
        """Testa extração do git SHA."""
        git_sha = use_case._get_git_sha()
        assert git_sha is None or len(git_sha) == 40

    def test_docker_version_extraction(self, use_case):
        """Testa extração da versão do Docker."""
        assert isinstance(use_case._get_docker_version(), str)


class _CompletedProcess:
    """Substituto de `subprocess.CompletedProcess` para os testes."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


TRIVY_OUTPUT = json.dumps(
    {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0001",
                        "PkgName": "openssl",
                        "Severity": "CRITICAL",
                        "InstalledVersion": "3.0.11",
                        "FixedVersion": "3.0.12",
                    },
                    {
                        "VulnerabilityID": "CVE-2026-0002",
                        "PkgName": "perl-base",
                        "Severity": "HIGH",
                        "InstalledVersion": "5.36.0",
                    },
                    {
                        "VulnerabilityID": "CVE-2026-0003",
                        "PkgName": "zlib",
                        "Severity": "MEDIUM",
                        "InstalledVersion": "1.2",
                        "FixedVersion": "1.3",
                    },
                    {
                        "VulnerabilityID": "CVE-2026-0004",
                        "PkgName": "bash",
                        "Severity": "LOW",
                        "InstalledVersion": "5.1",
                    },
                    {
                        "VulnerabilityID": "CVE-2026-0005",
                        "PkgName": "misc",
                        "Severity": "SOMETHING-ELSE",
                        "InstalledVersion": "1.0",
                    },
                ]
            }
        ]
    }
)


@pytest.fixture
def bare_use_case():
    return BuildImageUseCase(
        MagicMock(spec=DockerfileValidatorInterface), MagicMock(spec=HardeningTemplateProvider)
    )


class TestDockerBuildInvocation:
    """`docker build` é montado à mão; um argumento errado silenciosamente
    constrói a imagem errada."""

    def _run(self, use_case, options, **kwargs):
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
            patch.object(use_case, "_get_image_info", return_value={}),
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            run.return_value = _CompletedProcess(returncode=kwargs.get("returncode", 0))
            result = use_case._build_image(
                context_path=options.context_path,
                dockerfile_path=options.dockerfile_path,
                tag=options.tag,
                options=options,
            )
        return result, run

    def test_passes_tag_dockerfile_and_context(self, bare_use_case):
        options = BuildOptions(tag="app:1.0", dockerfile_path="Dockerfile", context_path="./ctx")
        _, run = self._run(bare_use_case, options)

        argv = run.call_args.args[0]
        assert argv[0] == "/usr/bin/docker"
        assert argv[1] == "build"
        assert argv[argv.index("-t") + 1] == "app:1.0"
        assert argv[argv.index("-f") + 1] == "Dockerfile"
        assert argv[-1] == "./ctx"

    def test_forwards_build_args_labels_and_no_cache(self, bare_use_case):
        options = BuildOptions(
            tag="app:1.0",
            no_cache=True,
            build_args={"NODE_ENV": "production"},
            labels={"org.opencontainers.image.source": "repo"},
        )
        _, run = self._run(bare_use_case, options)

        argv = run.call_args.args[0]
        assert "--no-cache" in argv
        assert "NODE_ENV=production" in argv
        assert "org.opencontainers.image.source=repo" in argv

    def test_enables_buildkit_through_the_environment(self, bare_use_case):
        """BuildKit é ligado por variável de ambiente; a flag antiga que o
        código montava e descartava nunca fez nada."""
        _, run = self._run(bare_use_case, BuildOptions(tag="app:1.0", buildkit=True))

        assert run.call_args.kwargs["env"]["DOCKER_BUILDKIT"] == "1"

    def test_non_zero_exit_is_a_failure_carrying_stderr(self, bare_use_case):
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            run.return_value = _CompletedProcess(returncode=1, stderr="no such file")
            result = bare_use_case._build_image(
                ".", "Dockerfile", "app:1", BuildOptions(tag="app:1")
            )

        assert result.success is False
        assert "no such file" in result.error_message

    def test_missing_docker_fails_with_a_named_message(self, bare_use_case):
        with patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve:
            resolve.side_effect = ExecutableNotFoundError("docker")
            result = bare_use_case._build_image(
                ".", "Dockerfile", "app:1", BuildOptions(tag="app:1")
            )

        assert result.success is False
        assert "docker" in result.error_message

    def test_timeout_is_reported_as_such(self, bare_use_case):
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            run.side_effect = subprocess.TimeoutExpired(cmd="docker", timeout=3600)
            result = bare_use_case._build_image(
                ".", "Dockerfile", "app:1", BuildOptions(tag="app:1")
            )

        assert result.success is False
        assert "timeout" in result.error_message.lower()


class TestScanParsing:
    """As contagens que saem daqui são as que `--fail-on` usa para reprovar
    um build. Um erro de parsing deixa passar a imagem que deveria barrar."""

    def test_counts_each_severity_and_the_fixable_ones(self, bare_use_case):
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            run.return_value = _CompletedProcess(returncode=0, stdout=TRIVY_OUTPUT)
            scan = bare_use_case._scan_image("app:1.0")

        assert scan is not None
        assert (scan.critical, scan.high, scan.medium, scan.low) == (1, 1, 1, 1)
        # Severidade desconhecida não pode ser descartada nem contada como LOW.
        assert scan.unknown == 1
        assert scan.total_vulnerabilities == 5
        assert scan.fixable == 2
        assert scan.scan_tool == "trivy"

    def test_falls_back_to_grype_when_trivy_is_absent(self, bare_use_case):
        def resolve(name):
            if name == "trivy":
                raise ExecutableNotFoundError("trivy")
            return f"/usr/bin/{name}"

        with (
            patch(
                "dockerls.application.use_cases.build_image.resolve_executable", side_effect=resolve
            ),
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            run.return_value = _CompletedProcess(returncode=0, stdout='{"matches": []}')
            scan = bare_use_case._scan_image("app:1.0")

        assert scan is not None
        assert scan.scan_tool == "grype"

    def test_returns_none_when_no_scanner_is_installed(self, bare_use_case):
        with patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve:
            resolve.side_effect = ExecutableNotFoundError("trivy")
            assert bare_use_case._scan_image("app:1.0") is None

    def test_malformed_scanner_output_does_not_raise(self, bare_use_case):
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            run.return_value = _CompletedProcess(returncode=0, stdout="not json")
            assert bare_use_case._scan_image("app:1.0") is None


class TestFailOnThreshold:
    @pytest.mark.parametrize(
        ("threshold", "scan", "expected"),
        [
            ("critical", ScanResult(critical=1), True),
            ("critical", ScanResult(high=9), False),
            ("high", ScanResult(high=1), True),
            ("high", ScanResult(critical=1), True),
            ("high", ScanResult(medium=50), False),
            ("medium", ScanResult(critical=1), False),
        ],
    )
    def test_threshold_semantics(self, bare_use_case, threshold, scan, expected):
        """`--fail-on high` também reprova em CRITICAL: um limiar que ignora
        o que é pior que ele não é um limiar."""
        assert bare_use_case._should_fail(scan, threshold) is expected


class TestImageInfo:
    def test_parses_docker_inspect_output(self, bare_use_case):
        payload = json.dumps([{"Id": "sha256:abc", "Size": 1234, "RootFS": {"Layers": ["a", "b"]}}])
        with (
            patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve,
            patch("dockerls.application.use_cases.build_image.subprocess.run") as run,
        ):
            resolve.side_effect = lambda name: f"/usr/bin/{name}"
            run.return_value = _CompletedProcess(returncode=0, stdout=payload)
            info = bare_use_case._get_image_info("app:1.0")

        assert info["Id"] == "sha256:abc"

    def test_missing_docker_degrades_to_empty_info(self, bare_use_case):
        with patch("dockerls.application.use_cases.build_image.resolve_executable") as resolve:
            resolve.side_effect = ExecutableNotFoundError("docker")
            assert bare_use_case._get_image_info("app:1.0") == {}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
