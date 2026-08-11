"""Testes para `dockerls/cli/rendering.py`.

`analyze-dockerfile` e `build --validate-only` renderizam o mesmo relatório
através deste módulo (ver `dockerls/cli/commands/analyze_dockerfile.py` e
`dockerls/cli/commands/build.py`). Estes testes fixam o contrato do
renderizador isoladamente, sem depender do comando CLI que o chama.
"""

from __future__ import annotations

from rich.console import Console

from dockerls.cli.rendering import render_validation_report
from dockerls.domain.entities.dockerfile_analysis import (
    DockerfileAnalysis,
    DockerfileInfo,
    DockerfileValidationResult,
    HardeningRule,
    SeverityLevel,
    ValidationCheck,
    ValidationStatus,
)


def _console() -> Console:
    # `record=True` lets the test pull back plain text via `export_text()`
    # instead of parsing ANSI escape codes; `no_color` keeps that text free
    # of markup noise entirely.
    return Console(record=True, width=100, no_color=True)


def _validation(
    checks: list[ValidationCheck] | None = None,
    dockerfile_path: str = "Dockerfile",
    passed: int = 1,
    warnings: int = 0,
    errors: int = 0,
) -> DockerfileValidationResult:
    return DockerfileValidationResult(
        dockerfile_path=dockerfile_path,
        passed=passed,
        warnings=warnings,
        errors=errors,
        checks=checks or [],
    )


class TestHeaderAndSummary:
    def test_default_title_and_path_are_rendered(self):
        console = _console()
        render_validation_report(console, _validation(dockerfile_path="app/Dockerfile"))
        text = console.export_text()

        assert "Dockerfile Analysis Report" in text
        assert "app/Dockerfile" in text

    def test_custom_title_replaces_the_default(self):
        console = _console()
        render_validation_report(console, _validation(), title="Dockerfile Validation")
        text = console.export_text()

        assert "Dockerfile Validation" in text
        assert "Dockerfile Analysis Report" not in text

    def test_empty_path_falls_back_to_a_placeholder(self):
        console = _console()
        render_validation_report(console, _validation(dockerfile_path=""))

        assert "Dockerfile" in console.export_text()

    def test_summary_counts_passed_warnings_and_errors(self):
        console = _console()
        render_validation_report(console, _validation(passed=3, warnings=2, errors=1))
        text = console.export_text()

        assert "3 passed" in text
        assert "2 warnings" in text
        assert "1 errors" in text


class TestChecksTable:
    def test_renders_every_status_icon(self):
        console = _console()
        checks = [
            ValidationCheck(check="base_image_pinned", status=ValidationStatus.PASS, message="ok"),
            ValidationCheck(
                check="no_latest_tag", status=ValidationStatus.WARN, message="uses :latest"
            ),
            ValidationCheck(
                check="non_root_user", status=ValidationStatus.FAIL, message="runs as root"
            ),
            ValidationCheck(check="healthcheck", status=ValidationStatus.SKIP, message="n/a"),
        ]
        render_validation_report(console, _validation(checks=checks))
        text = console.export_text()

        assert "Validation Checks" in text
        for check in checks:
            assert check.check in text
            assert check.message in text
        assert "PASS" in text
        assert "WARN" in text
        assert "FAIL" in text
        assert "SKIP" in text

    def test_severity_value_is_shown_for_each_check(self):
        console = _console()
        checks = [
            ValidationCheck(
                check="secrets_not_in_env",
                status=ValidationStatus.FAIL,
                message="ENV DOCKER_TOKEN detected",
                severity=SeverityLevel.CRITICAL,
            ),
        ]
        render_validation_report(console, _validation(checks=checks))

        assert "CRITICAL" in console.export_text()

    def test_no_checks_shows_a_placeholder_instead_of_an_empty_table(self):
        console = _console()
        render_validation_report(console, _validation(checks=[]))
        text = console.export_text()

        assert "No validation checks were produced" in text
        assert "Validation Checks" not in text


class TestSecurityScorePanel:
    def test_omitted_when_no_analysis_is_given(self):
        console = _console()
        checks = [ValidationCheck(check="x", status=ValidationStatus.PASS, message="ok")]
        render_validation_report(console, _validation(checks=checks), analysis=None)

        assert "Security Score" not in console.export_text()

    def test_shows_score_tier_and_production_ready_when_valid(self):
        console = _console()
        validation = _validation(errors=0)
        analysis = DockerfileAnalysis(
            info=DockerfileInfo(), validation=validation, security_score=92, security_tier="A"
        )
        render_validation_report(console, validation, analysis=analysis)
        text = console.export_text()

        assert "Security Score: 92/100" in text
        assert "Tier: A" in text
        assert "Production Ready: Yes" in text

    def test_production_not_ready_when_tier_is_low(self):
        console = _console()
        validation = _validation(errors=0)
        analysis = DockerfileAnalysis(
            info=DockerfileInfo(), validation=validation, security_score=40, security_tier="F"
        )
        render_validation_report(console, validation, analysis=analysis)

        assert "Production Ready: No" in console.export_text()

    def test_production_not_ready_when_validation_has_errors_despite_a_good_tier(self):
        console = _console()
        validation = _validation(errors=1)
        analysis = DockerfileAnalysis(
            info=DockerfileInfo(), validation=validation, security_score=95, security_tier="A"
        )
        render_validation_report(console, validation, analysis=analysis)

        assert "Production Ready: No" in console.export_text()


class TestSuggestions:
    def test_omitted_when_suggestions_is_none(self):
        console = _console()
        render_validation_report(console, _validation(), suggestions=None)

        assert "Recommendations" not in console.export_text()

    def test_omitted_when_suggestions_is_an_empty_list(self):
        console = _console()
        render_validation_report(console, _validation(), suggestions=[])

        assert "Recommendations" not in console.export_text()

    def test_renders_every_field_of_each_suggestion(self):
        console = _console()
        suggestion = HardeningRule(
            priority=SeverityLevel.CRITICAL,
            title="Remove secrets from ENV",
            description="Secrets belong in --secret, not ENV",
            current_state="ENV DOCKER_TOKEN=dckr_pat_example",
            suggested_fix="Use --mount=type=secret",
            reason="ENV values are baked into image history",
        )
        render_validation_report(console, _validation(), suggestions=[suggestion])
        text = console.export_text()

        assert "Recommendations" in text
        assert "#1. Remove secrets from ENV" in text
        assert "Secrets belong in --secret, not ENV" in text
        assert "ENV DOCKER_TOKEN=dckr_pat_example" in text
        assert "Use --mount=type=secret" in text
        assert "ENV values are baked into image history" in text

    def test_multiple_suggestions_are_numbered_in_order(self):
        console = _console()
        suggestions = [
            HardeningRule(
                priority=SeverityLevel.HIGH,
                title="Add non-root user",
                description="d1",
                current_state="root",
                suggested_fix="USER app",
                reason="r1",
            ),
            HardeningRule(
                priority=SeverityLevel.LOW,
                title="Clean package cache",
                description="d2",
                current_state="not cleaned",
                suggested_fix="rm -rf /var/cache/apk/*",
                reason="r2",
            ),
        ]
        render_validation_report(console, _validation(), suggestions=suggestions)
        text = console.export_text()

        assert "#1. Add non-root user" in text
        assert "#2. Clean package cache" in text
