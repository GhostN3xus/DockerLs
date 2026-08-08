"""Interfaces para validação de Dockerfiles."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dockerls.domain.entities.dockerfile_analysis import (
        DockerfileAnalysis,
        DockerfileValidationResult,
        HardeningRule,
    )


class DockerfileValidatorInterface(ABC):
    """Interface para validadores de Dockerfile."""

    @abstractmethod
    def validate(self, dockerfile_path: str | Path) -> DockerfileValidationResult:
        """Valida um Dockerfile contra regras OWASP.

        Args:
            dockerfile_path: Caminho para o Dockerfile ou diretório contendo Dockerfile.

        Returns:
            Resultado da validação com checks, warnings e errors.
        """
        pass

    @abstractmethod
    def analyze(self, dockerfile_path: str | Path) -> DockerfileAnalysis:
        """Analisa um Dockerfile e retorna análise completa.

        Args:
            dockerfile_path: Caminho para o Dockerfile ou diretório contendo Dockerfile.

        Returns:
            Análise completa incluindo info, validação e score de segurança.
        """
        pass

    @abstractmethod
    def suggest_hardening(self, dockerfile_path: str | Path) -> list[HardeningRule]:
        """Sugere melhorias de hardening para um Dockerfile.

        Args:
            dockerfile_path: Caminho para o Dockerfile ou diretório contendo Dockerfile.

        Returns:
            Lista de regras de hardening sugeridas.
        """
        pass


class HardeningTemplateProvider(ABC):
    """Interface para provedores de templates hardened."""

    @abstractmethod
    def get_template(self, base_image: str) -> str:
        """Retorna template hardened para um tipo de base image.

        Args:
            base_image: Nome da imagem base (ex: node, python, go).

        Returns:
            Conteúdo do template Dockerfile hardened.
        """
        pass

    @abstractmethod
    def list_templates(self) -> list[str]:
        """Lista todos os templates disponíveis.

        Returns:
            Lista de nomes de templates disponíveis.
        """
        pass

    @abstractmethod
    def generate_hardened_dockerfile(
        self,
        dockerfile_path: str | Path,
        base_image: str | None = None,
        output_path: str | Path | None = None,
    ) -> str:
        """Gera um Dockerfile hardened baseado no original ou template.

        Args:
            dockerfile_path: Caminho para o Dockerfile original.
            base_image: Imagem base para usar no template (opcional).
            output_path: Caminho para salvar o novo Dockerfile (opcional).

        Returns:
            Conteúdo do Dockerfile hardened gerado.
        """
        pass
