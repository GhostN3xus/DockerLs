"""Static analysis of a Dockerfile: what it does, and what to change.

This is the only path that produces validation findings. `dockerls build`
runs it before every build, and `--validate-only` / `--suggest-hardening`
run it *instead* of one, so the gate and the advice can never be computed
two different ways.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from dockerls.domain.entities.build_validation import ValidationResult
from dockerls.domain.entities.hardening_rule import HardeningRule
from dockerls.infrastructure.dockerfile.parser import DockerfileParseError, find_dockerfile

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.domain.interfaces.dockerfile_validator import DockerfileValidatorInterface


class DockerfileAnalysis(BaseModel):
    dockerfile_path: str
    context_path: str
    validation: ValidationResult
    recommendations: list[HardeningRule] = Field(default_factory=list)


class AnalyzeDockerfileUseCase:
    def __init__(self, validator: DockerfileValidatorInterface):
        self._validator = validator

    def resolve(self, context: Path, explicit: Path | None = None) -> tuple[Path, Path]:
        """Locate the Dockerfile and its build context.

        Returns (dockerfile, context_dir). `dockerls build ./Dockerfile`
        names the file, and the context is then the directory holding it --
        the same resolution `docker build` performs.
        """
        try:
            dockerfile = find_dockerfile(context, explicit)
        except DockerfileParseError as e:
            raise ValueError(str(e)) from e
        context_dir = context if context.is_dir() else dockerfile.parent
        return dockerfile, context_dir

    def execute(self, context: Path, explicit: Path | None = None) -> DockerfileAnalysis:
        dockerfile, context_dir = self.resolve(context, explicit)
        return DockerfileAnalysis(
            dockerfile_path=str(dockerfile),
            context_path=str(context_dir),
            validation=self._validator.validate(dockerfile, context_dir),
            recommendations=self._validator.suggest_hardening(dockerfile, context_dir),
        )
