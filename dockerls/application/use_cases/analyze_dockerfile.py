"""Use case para análise de Dockerfiles."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dockerls.domain.entities.dockerfile_analysis import (
        DockerfileAnalysis,
        DockerfileValidationResult,
        HardeningRule,
    )
    from dockerls.domain.interfaces.dockerfile_validator import (
        DockerfileValidatorInterface,
        HardeningTemplateProvider,
    )


@dataclass
class AnalyzeDockerfileRequest:
    """Request para análise de Dockerfile."""

    dockerfile_path: str | Path
    include_suggestions: bool = True
    validate_only: bool = False


@dataclass
class AnalyzeDockerfileResponse:
    """Resposta da análise de Dockerfile."""

    success: bool
    analysis: DockerfileAnalysis | None = None
    validation: DockerfileValidationResult | None = None
    suggestions: list[HardeningRule] | None = None
    error: str | None = None

    def model_dump(self) -> dict:
        """Retorna dicionário serializável."""
        return {
            "success": self.success,
            "analysis": self.analysis.model_dump() if self.analysis else None,
            "validation": self.validation.model_dump() if self.validation else None,
            "suggestions": [s.model_dump() for s in self.suggestions] if self.suggestions else [],
            "error": self.error,
        }


class AnalyzeDockerfileUseCase:
    """Caso de uso para análise de Dockerfiles."""

    def __init__(
        self,
        validator: DockerfileValidatorInterface,
        template_provider: HardeningTemplateProvider | None = None,
    ):
        self._validator = validator
        self._template_provider = template_provider

    def execute(self, request: AnalyzeDockerfileRequest) -> AnalyzeDockerfileResponse:
        """Executa a análise do Dockerfile."""
        try:
            path = Path(request.dockerfile_path)
            if path.is_dir():
                path = path / "Dockerfile"

            if not path.exists():
                return AnalyzeDockerfileResponse(
                    success=False,
                    error=f"Dockerfile not found at {path}",
                )

            # Validação sempre é executada
            validation = self._validator.validate(path)

            if request.validate_only:
                return AnalyzeDockerfileResponse(
                    success=True,
                    validation=validation,
                )

            # Análise completa
            analysis = self._validator.analyze(path)

            # Sugestões se solicitado
            suggestions = []
            if request.include_suggestions:
                suggestions = self._validator.suggest_hardening(path)

            return AnalyzeDockerfileResponse(
                success=True,
                analysis=analysis,
                validation=validation,
                suggestions=suggestions,
            )

        except Exception as e:
            return AnalyzeDockerfileResponse(
                success=False,
                error=str(e),
            )
