from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.domain.entities.build_validation import ValidationResult
    from dockerls.domain.entities.hardening_rule import HardeningRule


class DockerfileValidatorInterface(ABC):
    """Evaluates a Dockerfile against the project's security rule set."""

    @abstractmethod
    def validate(self, path: Path, context: Path | None = None) -> ValidationResult:
        """Run every rule. `context` is the build context directory, needed
        by rules that inspect files next to the Dockerfile (.dockerignore)."""

    @abstractmethod
    def suggest_hardening(self, path: Path, context: Path | None = None) -> list[HardeningRule]:
        """Actionable improvements, ordered most important first. Never
        blocks anything -- these are recommendations, not verdicts."""
