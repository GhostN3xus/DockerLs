"""`dockerls templates generate` -- write a hardened Dockerfile into a project.

Generation never overwrites. A Dockerfile is the thing being fixed, and a
tool that silently replaces it destroys the only record of what the project
was actually doing. The generated file lands beside the original as
`Dockerfile.hardened` unless the caller explicitly asks otherwise.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from loguru import logger
from pydantic import BaseModel

from dockerls.infrastructure.templates.loader import (
    DEFAULT_DOCKERIGNORE,
    DETECTION_MARKERS,
    get_template,
)

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.domain.interfaces.dockerfile_validator import DockerfileValidatorInterface

DEFAULT_OUTPUT_NAME = "Dockerfile.hardened"


class GeneratedTemplate(BaseModel):
    template: str
    dockerfile_path: str
    dockerignore_path: str = ""
    detected_from: str = ""
    # Validation of the file that was just written, so `generate` proves the
    # template it produced actually clears the rule set rather than asserting it.
    checks_passed: int = 0
    checks_total: int = 0
    overwritten: bool = False


class TemplateGenerationError(RuntimeError):
    pass


class GenerateHardenedDockerfileUseCase:
    def __init__(self, validator: DockerfileValidatorInterface | None = None):
        self._validator = validator

    def detect(self, context: Path) -> str:
        """Guess the project's runtime from the files it contains."""
        for template_name, marker in DETECTION_MARKERS:
            if (context / marker).exists():
                return template_name
        return ""

    def execute(
        self,
        context: Path,
        base: str = "",
        output: Path | None = None,
        write_dockerignore: bool = True,
        force: bool = False,
    ) -> GeneratedTemplate:
        if not context.is_dir():
            raise TemplateGenerationError(f"Not a directory: {context}")

        detected = ""
        if not base:
            detected = self.detect(context)
            if not detected:
                raise TemplateGenerationError(
                    "Could not detect the project type. Pass one explicitly, e.g. --base node."
                )
            base = detected

        try:
            template = get_template(base)
        except ValueError as e:
            raise TemplateGenerationError(str(e)) from e

        target = output or context / DEFAULT_OUTPUT_NAME
        overwritten = target.exists()
        if overwritten and not force:
            raise TemplateGenerationError(
                f"{target} already exists. Re-run with --force to replace it."
            )

        try:
            target.write_text(template.read(), encoding="utf-8")
        except OSError as e:
            raise TemplateGenerationError(f"Could not write {target}: {e}") from e
        logger.info(f"Wrote hardened {template.name} Dockerfile to {target}")

        ignore_path = self._write_dockerignore(context) if write_dockerignore else ""
        passed, total = self._verify(target, context)
        return GeneratedTemplate(
            template=template.name,
            dockerfile_path=str(target),
            dockerignore_path=ignore_path,
            detected_from=detected,
            checks_passed=passed,
            checks_total=total,
            overwritten=overwritten,
        )

    def _write_dockerignore(self, context: Path) -> str:
        """Create a .dockerignore only when the project has none.

        An existing one is the project's decision and may well be stricter
        than the default; replacing it could start shipping files the
        project had deliberately excluded.
        """
        path = context / ".dockerignore"
        if path.exists():
            return ""
        try:
            path.write_text(DEFAULT_DOCKERIGNORE, encoding="utf-8")
        except OSError as e:
            logger.warning(f"Could not write {path}: {e}")
            return ""
        return str(path)

    def _verify(self, dockerfile: Path, context: Path) -> tuple[int, int]:
        if self._validator is None:
            return 0, 0
        result = self._validator.validate(dockerfile, context)
        return len(result.passed), result.evaluated_count
