"""Testes para o BuildImageUseCase.

Os fixtures mockam `DockerfileValidatorInterface`, que é o que o caso de uso
realmente depende. Antes eles devolviam de `validate()` um objeto no formato
de `AnalyzeDockerfileResponse`; como `BuildImageUseCase` instancia um
`AnalyzeDockerfileUseCase` internamente, esse retorno era envelopado numa
segunda camada e `response.validation.errors` caía num `MagicMock`, que nunca
é igual a `0` -- então todo cenário "sem erros" chegava como reprovado.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dockerls.application.use_cases.analyze_dockerfile import AnalyzeDockerfileResponse
from dockerls.application.use_cases.build_image import (
    BuildImageRequest,
    BuildImageUseCase,
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
