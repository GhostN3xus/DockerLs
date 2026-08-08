"""Testes para o BuildImageUseCase."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dockerls.application.use_cases.build_image import (
    BuildImageRequest,
    BuildImageResponse,
    BuildImageUseCase,
)
from dockerls.domain.entities.dockerfile_analysis import (
    DockerfileInfo,
    DockerfileValidationResult,
    ValidationCheck,
    ValidationStatus,
)
from dockerls.infrastructure.dockerfile_validator import DockerfileValidator, HardeningTemplates


class TestBuildImageUseCase:
    """Testes para o caso de uso de build de imagem."""

    @pytest.fixture
    def validator(self):
        """Retorna um mock do validador."""
        return MagicMock(spec=DockerfileValidator)

    @pytest.fixture
    def template_provider(self):
        """Retorna um mock do provedor de templates."""
        return MagicMock(spec=HardeningTemplates)

    @pytest.fixture
    def use_case(self, validator, template_provider):
        """Retorna uma instância do use case."""
        return BuildImageUseCase(validator, template_provider)

    def test_build_valid_dockerfile_succeeds(self, use_case, validator, template_provider):
        """Build de Dockerfile válido deve suceder."""
        # Setup: mock validation result - usando analyze ao invés de validate
        from dockerls.application.use_cases.analyze_dockerfile import AnalyzeDockerfileResponse
        
        validation_result = MagicMock()
        validation_result.validation = DockerfileValidationResult(
            dockerfile_path="Dockerfile",
            passed=10,
            warnings=0,
            errors=0,
        )
        validation_result.analysis = None
        validation_result.suggestions = []
        validation_result.success = True
        validation_result.error = None

        # Mock do analyze_dockerfile que é chamado internamente
        with patch.object(use_case, '_validate_dockerfile', return_value=validation_result):
            request = BuildImageRequest(
                context_path=".",
                tag="test:latest",
                validate_only=True,
            )

            response = use_case.execute(request)

            assert response.success is True
            assert response.exit_code == 0

    def test_validation_fails_on_secrets_in_env(self, use_case, validator, template_provider):
        """Deve rejeitar secrets em ENV."""
        # Setup: mock validation with errors
        validation_result = MagicMock()
        validation_result.validation = DockerfileValidationResult(
            dockerfile_path="Dockerfile",
            passed=8,
            warnings=0,
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
        validation_result.analysis = None
        validation_result.suggestions = []

        validator.validate.return_value = validation_result

        request = BuildImageRequest(
            context_path=".",
            tag="test:latest",
            validate_only=True,
        )

        response = use_case.execute(request)

        assert response.success is False
        assert response.exit_code == 1
        assert "validation failed" in response.error.lower()

    def test_validation_warns_on_latest_tag(self, use_case, validator, template_provider):
        """Deve avisar sobre latest tag."""
        # Setup: mock validation with warnings
        validation_result = MagicMock()
        validation_result.validation = DockerfileValidationResult(
            dockerfile_path="Dockerfile",
            passed=9,
            warnings=1,
            errors=0,
            checks=[
                ValidationCheck(
                    check="no_latest_tag",
                    status=ValidationStatus.WARN,
                    message="Base image uses :latest tag",
                ),
            ],
        )
        validation_result.analysis = None
        validation_result.suggestions = []

        validator.validate.return_value = validation_result

        request = BuildImageRequest(
            context_path=".",
            tag="test:latest",
            validate_only=True,
        )

        response = use_case.execute(request)

        # Warnings não falham o build
        assert response.success is True
        assert response.exit_code == 0

    def test_suggests_hardening_rules(self, use_case, validator, template_provider):
        """Deve sugerir melhorias de hardening."""
        # Setup: mock validation with suggestions
        from dockerls.domain.entities.dockerfile_analysis import HardeningRule, SeverityLevel

        validation_result = MagicMock()
        validation_result.validation = DockerfileValidationResult(
            dockerfile_path="Dockerfile",
            passed=8,
            warnings=2,
            errors=0,
        )
        validation_result.analysis = None
        validation_result.suggestions = [
            HardeningRule(
                priority=SeverityLevel.HIGH,
                title="Add non-root user",
                description="Container should run as non-root",
                current_state="Running as root",
                suggested_fix="USER appuser",
                reason="Security best practice",
            ),
        ]

        validator.validate.return_value = validation_result

        request = BuildImageRequest(
            context_path=".",
            tag="test:latest",
            suggest_only=True,
        )

        response = use_case.execute(request)

        assert response.success is True
        assert len(response.recommendations) > 0

    def test_generates_hardened_dockerfile(self, use_case, validator, template_provider, tmp_path):
        """Template hardened deve gerar Dockerfile.hardened válido."""
        # Setup: mock validation
        validation_result = MagicMock()
        validation_result.validation = DockerfileValidationResult(
            dockerfile_path="Dockerfile",
            passed=10,
            warnings=0,
            errors=0,
        )
        validation_result.analysis = None
        validation_result.suggestions = []

        validator.validate.return_value = validation_result

        # Mock template
        template_content = """FROM node:22-alpine
WORKDIR /app
COPY . .
RUN npm install
USER node
CMD ["node", "index.js"]
"""
        template_provider.get_template.return_value = template_content

        # Create temp directory
        context_path = tmp_path
        (context_path / "Dockerfile").write_text("FROM node:latest")

        request = BuildImageRequest(
            context_path=str(context_path),
            tag="test:latest",
            hardened=True,
            base_template="node",
            validate_only=True,
        )

        response = use_case.execute(request)

        # Check hardened Dockerfile was created
        hardened_path = context_path / "Dockerfile.hardened"
        assert hardened_path.exists()
        assert hardened_path.read_text() == template_content

    def test_ci_mode_returns_json_only(self, use_case, validator, template_provider):
        """CI mode deve retornar apenas JSON (sem cores)."""
        validation_result = MagicMock()
        validation_result.validation = DockerfileValidationResult(
            dockerfile_path="Dockerfile",
            passed=10,
            warnings=0,
            errors=0,
        )
        validation_result.analysis = None
        validation_result.suggestions = []

        validator.validate.return_value = validation_result

        request = BuildImageRequest(
            context_path=".",
            tag="test:latest",
            ci_mode=True,
            validate_only=True,
        )

        response = use_case.execute(request)

        assert response.success is True
        # CI mode output is handled in CLI, not use case
        assert response.exit_code == 0

    def test_fail_on_critical_reproofs_build(self, use_case, validator, template_provider):
        """--fail-on critical deve retornar código 1 se tiver CRITICAL."""
        # Setup: mock validation passing but scan failing
        validation_result = MagicMock()
        validation_result.validation = DockerfileValidationResult(
            dockerfile_path="Dockerfile",
            passed=10,
            warnings=0,
            errors=0,
        )
        validation_result.analysis = None
        validation_result.suggestions = []

        validator.validate.return_value = validation_result

        # Mock scan result with critical vulns
        with patch.object(use_case, '_scan_image') as mock_scan:
            from dockerls.application.use_cases.build_image import ScanResult

            mock_scan.return_value = ScanResult(
                critical=2,
                high=0,
                medium=5,
                low=10,
            )

            request = BuildImageRequest(
                context_path=".",
                tag="test:latest",
                scan=True,
                fail_on="critical",
            )

            # Simulate build success
            with patch.object(use_case, '_build_image') as mock_build:
                from dockerls.application.use_cases.build_image import BuildResult

                mock_build.return_value = BuildResult(
                    success=True,
                    image_tag="test:latest",
                    image_sha256="sha256:abc123",
                )

                response = use_case.execute(request)

                assert response.success is False
                assert "Vulnerabilities exceed threshold" in response.error

    def test_security_score_calculation(self, use_case):
        """Testa cálculo do security score."""
        # Setup validation and scan results
        validation_result = MagicMock()
        validation_result.validation = DockerfileValidationResult(
            dockerfile_path="Dockerfile",
            passed=8,
            warnings=2,
            errors=0,
        )

        from dockerls.application.use_cases.build_image import ScanResult

        scan_result = ScanResult(
            critical=0,
            high=1,
            medium=3,
            low=5,
        )

        # Calculate score manually
        score = use_case._calculate_security_score(validation_result, scan_result)

        # Expected: 100 - (0*10) - (2*3) - (0*15) - (1*10) - (3*3) - (5*1)
        # = 100 - 0 - 6 - 0 - 10 - 9 - 5 = 70
        assert score == 70

    def test_security_tier_calculation(self, use_case):
        """Testa cálculo do security tier."""
        assert use_case._calculate_security_tier(95) == "A"
        assert use_case._calculate_security_tier(80) == "B"
        assert use_case._calculate_security_tier(65) == "C"
        assert use_case._calculate_security_tier(50) == "D"
        assert use_case._calculate_security_tier(30) == "F"

    def test_report_generation(self, use_case, validator, template_provider):
        """Deve gerar relatório JSON válido."""
        from datetime import datetime

        # Setup mocks
        validation_result = MagicMock()
        validation_result.validation = DockerfileValidationResult(
            dockerfile_path="Dockerfile",
            passed=10,
            warnings=0,
            errors=0,
            checks=[],
        )
        validation_result.analysis = None
        validation_result.suggestions = []

        validator.validate.return_value = validation_result

        from dockerls.application.use_cases.build_image import BuildResult, ScanResult

        build_result = BuildResult(
            success=True,
            image_tag="test:latest",
            image_sha256="sha256:abc123",
            build_time_seconds=45.0,
        )

        scan_result = ScanResult(
            critical=0,
            high=0,
            medium=2,
            low=5,
        )

        report = use_case._generate_report(
            validation=validation_result,
            build=build_result,
            scan=scan_result,
            image_tag="test:latest",
            dockerfile_path="Dockerfile",
        )

        # Verify report structure
        assert report.build_id is not None
        assert report.timestamp is not None
        assert report.image == "test:latest"
        assert report.security_score > 0
        assert report.security_tier in ["A", "B", "C", "D", "F"]
        assert isinstance(report.validation, dict)
        assert report.scan_results is not None

    def test_git_sha_extraction(self, use_case):
        """Testa extração do git SHA."""
        git_sha = use_case._get_git_sha()
        # Should return None or a valid SHA
        assert git_sha is None or len(git_sha) == 40

    def test_docker_version_extraction(self, use_case):
        """Testa extração da versão do Docker."""
        docker_version = use_case._get_docker_version()
        # Should return "unknown" or a version string
        assert isinstance(docker_version, str)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
