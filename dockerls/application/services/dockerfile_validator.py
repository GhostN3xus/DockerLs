from __future__ import annotations

from typing import TYPE_CHECKING

from loguru import logger

from dockerls.domain.entities.build_validation import (
    CheckStatus,
    HardeningLevel,
    ValidationCheck,
    ValidationResult,
)
from dockerls.domain.entities.vulnerability import Severity
from dockerls.domain.interfaces.dockerfile_validator import DockerfileValidatorInterface
from dockerls.infrastructure.dockerfile.parser import (
    DockerfileParseError,
    parse_dockerfile,
)
from dockerls.infrastructure.validators.dockerfile_security_rules import (
    SECURITY_RULES,
    RuleContext,
)

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from dockerls.application.services.hardening_suggester import HardeningSuggester
    from dockerls.domain.entities.dockerfile_analysis import ParsedDockerfile
    from dockerls.domain.entities.hardening_rule import HardeningRule


def _waived(rule_id: str, title: str) -> ValidationCheck:
    return ValidationCheck(
        check=rule_id,
        title=title,
        status=CheckStatus.SKIP,
        message="Waived by the project's hardening policy (validation.skip_rules)",
    )


class OwaspDockerfileValidator(DockerfileValidatorInterface):
    """Runs the OWASP-derived rule set over a Dockerfile.

    Parsing happens once per path and is shared between `validate` and
    `suggest_hardening`, so `--suggest-hardening` and the validation table
    can never describe two different readings of the same file.
    """

    def __init__(
        self,
        hardening_level: HardeningLevel = HardeningLevel.STANDARD,
        suggester: HardeningSuggester | None = None,
        skip_rules: Iterable[str] | None = None,
    ):
        self._level = hardening_level
        self._suggester = suggester
        # A rule the project has chosen not to enforce still appears in the
        # report, as SKIP. Dropping it would make the waiver invisible in
        # exactly the artefact an auditor reads.
        self._skip_rules = {r.strip() for r in (skip_rules or ()) if r.strip()}
        self._cache: dict[str, ParsedDockerfile] = {}

    def parse(self, path: Path) -> ParsedDockerfile:
        key = str(path)
        if key not in self._cache:
            self._cache[key] = parse_dockerfile(path)
        return self._cache[key]

    def validate(self, path: Path, context: Path | None = None) -> ValidationResult:
        try:
            parsed = self.parse(path)
        except DockerfileParseError as e:
            # An unparseable Dockerfile is reported as a finding rather than
            # raised: the caller still needs a result object to render, and
            # "could not be read" is itself the most severe possible verdict.
            logger.error(f"Dockerfile parse failed for {path}: {e}")
            return ValidationResult(
                dockerfile_path=str(path),
                hardening_level=self._level,
                parse_errors=[str(e)],
                checks=[
                    ValidationCheck(
                        check="dockerfile_parseable",
                        title="Dockerfile can be parsed",
                        status=CheckStatus.FAIL,
                        severity=Severity.CRITICAL,
                        message=str(e),
                        fix="Confirm the path points at a readable Dockerfile.",
                    )
                ],
            )

        ctx = RuleContext(dockerfile=parsed, context_dir=context)
        checks = [
            rule.run(ctx)
            if rule.rule_id not in self._skip_rules
            else _waived(rule.rule_id, rule.title)
            for rule in SECURITY_RULES
        ]
        return ValidationResult(
            dockerfile_path=str(path),
            checks=checks,
            hardening_level=self._level,
            parse_errors=parsed.parse_errors,
        )

    def suggest_hardening(self, path: Path, context: Path | None = None) -> list[HardeningRule]:
        from dockerls.application.services.hardening_suggester import HardeningSuggester

        suggester = self._suggester or HardeningSuggester()
        result = self.validate(path, context)
        try:
            parsed: ParsedDockerfile | None = self.parse(path)
        except DockerfileParseError:
            parsed = None
        return suggester.suggest(result, parsed)
