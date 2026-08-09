"""Testes do comando `build`.

O defeito que motivou estes testes: `build --validate-only` imprimia
literalmente `None` e mais nada — nem a tabela de checks, nem qual regra
falhou —, e o contrato de exit code não existia. Nada disso era coberto,
então nada disso quebrou nenhum teste.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from dockerls.application.use_cases.build_image import BuildImageResponse, BuildReport
from dockerls.cli.app import app
from dockerls.cli.commands.build import BuildImageUseCase
from dockerls.domain.entities.dockerfile_analysis import HardeningRule, SeverityLevel
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY

runner = CliRunner()

CLEAN_DOCKERFILE = """\
FROM node:22-alpine AS builder
WORKDIR /app
RUN npm ci --no-cache-dir && rm -rf ~/.cache/pip

FROM node:22-alpine
LABEL security.scanner="dockerls"
LABEL maintainer="team@example.com"
COPY --from=builder /app /app
USER node
HEALTHCHECK --interval=30s CMD ["node", "healthcheck.js"]
ENTRYPOINT ["node", "index.js"]
"""

# Reprova em três regras: base :latest, root, e segredos em ENV.
BAD_DOCKERFILE = """\
FROM node:latest
ENV DOCKER_TOKEN=dckr_pat_example
ENV API_KEY=abc123
RUN apt-get update && apt-get install -y curl
CMD npm start
"""


@pytest.fixture
def clean_context(tmp_path):
    (tmp_path / "Dockerfile").write_text(CLEAN_DOCKERFILE)
    (tmp_path / ".dockerignore").write_text("node_modules\n")
    return tmp_path


@pytest.fixture
def bad_context(tmp_path):
    (tmp_path / "Dockerfile").write_text(BAD_DOCKERFILE)
    return tmp_path


class TestValidateOnly:
    def test_clean_dockerfile_passes_with_the_checks_table(self, clean_context):
        result = runner.invoke(app, ["build", "--validate-only", str(clean_context)])

        assert result.exit_code == EXIT_OK
        assert "Validation Checks" in result.stdout
        assert "non_root_user" in result.stdout
        assert "Validation Passed" in result.stdout

    def test_output_never_contains_the_string_none(self, clean_context):
        """O sintoma original: um `None` solto onde deveria estar o relatório."""
        result = runner.invoke(app, ["build", "--validate-only", str(clean_context)])

        assert "None" not in result.stdout

    def test_failing_dockerfile_names_every_violated_rule(self, bad_context):
        result = runner.invoke(app, ["build", "--validate-only", str(bad_context)])

        # Política violada -- a validação rodou bem, o Dockerfile é que reprova.
        assert result.exit_code == EXIT_POLICY
        assert "Validation Failed" in result.stdout
        for rule in ("base_image_pinned", "non_root_user", "secrets_not_in_env"):
            assert rule in result.stdout
        assert "None" not in result.stdout

    def test_missing_dockerfile_is_an_execution_error(self, tmp_path):
        result = runner.invoke(app, ["build", "--validate-only", str(tmp_path)])

        assert result.exit_code == EXIT_ERROR
        assert "not found" in result.stdout.lower()

    def test_secret_values_are_not_echoed_back(self, bad_context):
        """Reportar o nome da variável é o objetivo; imprimir o valor dela
        transformaria o relatório num vazamento a mais."""
        result = runner.invoke(app, ["build", "--validate-only", str(bad_context)])

        assert "DOCKER_TOKEN" in result.stdout
        assert "dckr_pat_example" not in result.stdout


class TestCiMode:
    def test_emits_parseable_json_on_stdout(self, clean_context):
        result = runner.invoke(app, ["build", "--validate-only", "--ci-mode", str(clean_context)])

        assert result.exit_code == EXIT_OK
        payload = json.loads(result.stdout)
        assert payload["status"] == "SUCCESS"
        assert payload["exit_code"] == EXIT_OK
        assert payload["report"]["validation"]["errors"] == 0

    def test_failed_validation_still_carries_the_report(self, bad_context):
        """É exatamente quando reprova que o CI precisa do relatório: sem ele
        o pipeline sabe que falhou e não sabe em quê."""
        result = runner.invoke(app, ["build", "--validate-only", "--ci-mode", str(bad_context)])

        assert result.exit_code == EXIT_POLICY
        payload = json.loads(result.stdout)
        assert payload["status"] == "FAILED"
        failed = [c["check"] for c in payload["report"]["validation"]["checks"] if c["status"] == "FAIL"]
        assert "secrets_not_in_env" in failed
        assert "secrets_not_in_env" in payload["error"]

    def test_output_has_no_table_borders(self, clean_context):
        result = runner.invoke(app, ["build", "--validate-only", "--ci-mode", str(clean_context)])

        assert "┏" not in result.stdout
        assert "│" not in result.stdout


class TestSuggestHardening:
    def test_lists_recommendations_without_building(self, bad_context):
        result = runner.invoke(app, ["build", "--suggest-hardening", str(bad_context)])

        assert result.exit_code == EXIT_OK
        assert "Recommendations" in result.stdout
        assert "Remove secrets from ENV" in result.stdout
        assert "None" not in result.stdout


class TestListTemplates:
    def test_lists_the_templates_base_accepts(self):
        result = runner.invoke(app, ["build", "--list-templates"])

        assert result.exit_code == EXIT_OK
        for template in ("node", "python", "go", "java"):
            assert template in result.stdout

    def test_ci_mode_lists_them_as_json(self):
        result = runner.invoke(app, ["build", "--list-templates", "--ci-mode"])

        assert result.exit_code == EXIT_OK
        assert "node" in json.loads(result.stdout)["templates"]


class TestArgumentErrors:
    def test_build_without_tag_exits_one(self, clean_context):
        result = runner.invoke(app, ["build", str(clean_context)])

        assert result.exit_code == EXIT_ERROR
        assert "--tag" in result.stdout

    def test_malformed_build_args_json_exits_one(self, clean_context):
        result = runner.invoke(
            app, ["build", "-t", "x:1", "--build-args", "{nope", str(clean_context)]
        )

        assert result.exit_code == EXIT_ERROR
        assert "--build-args" in result.stdout

    def test_malformed_labels_json_exits_one(self, clean_context):
        result = runner.invoke(app, ["build", "-t", "x:1", "--labels", "{nope", str(clean_context)])

        assert result.exit_code == EXIT_ERROR
        assert "--labels" in result.stdout


class TestReportFile:
    def test_json_report_is_written_for_a_validation_run(self, bad_context, tmp_path):
        out = tmp_path / "report.json"
        result = runner.invoke(
            app, ["build", "--validate-only", "--report", str(out), str(bad_context)]
        )

        assert result.exit_code == EXIT_POLICY
        report = json.loads(out.read_text())
        assert report["validation"]["errors"] > 0
        assert report["security_tier"] in {"A", "B", "C", "D", "F"}

    def test_html_report_is_written(self, bad_context, tmp_path):
        out = tmp_path / "report.html"
        runner.invoke(app, ["build", "--validate-only", "--report", str(out), str(bad_context)])

        html = out.read_text()
        assert html.startswith("<!DOCTYPE html>")
        assert "DockerLs Build Report" in html

    def test_output_flag_writes_json_and_prints_no_table(self, clean_context, tmp_path):
        out = tmp_path / "ci.json"
        result = runner.invoke(
            app, ["build", "--validate-only", "--output", str(out), str(clean_context)]
        )

        assert result.exit_code == EXIT_OK
        assert json.loads(out.read_text())["status"] == "SUCCESS"
        assert "Validation Checks" not in result.stdout


def _build_report(**overrides) -> BuildReport:
    defaults: dict = dict(
        build_id="deadbeef01234567",
        timestamp="2026-01-01T00:00:00+00:00",
        image="myapp:1.0",
        dockerfile_path="Dockerfile",
        validation={
            "dockerfile_path": "Dockerfile",
            "passed": 5,
            "warnings": 0,
            "errors": 0,
            "checks": [],
        },
        scan_results={"trivy": {"critical": 0, "high": 1, "medium": 2, "low": 3}},
        security_score=88,
        security_tier="B",
        recommendations=[
            {
                "priority": "HIGH",
                "title": "Pin base image",
                "current": "node:latest",
                "suggested": "node:22-alpine",
                "reason": "Floating tags drift under you",
            }
        ],
        build_metadata={
            "git_sha": "deadbeef",
            "built_by": "ci",
            "docker_version": "Docker version 24.0.0",
            "buildkit": True,
        },
    )
    defaults.update(overrides)
    return BuildReport(**defaults)


class TestFullBuildFlow:
    """The real build path: `_print_build_output`, `_print_report`, and the
    HTML/JSON report writers. Every other class in this file only exercises
    `validate-only`/`suggest-hardening`/`list-templates`, none of which ever
    reach these functions.
    """

    def test_successful_build_renders_the_security_score_and_scan_results(
        self, clean_context, monkeypatch
    ):
        response = BuildImageResponse(
            success=True,
            image_tag="myapp:1.0",
            image_sha256="sha256:deadbeef",
            report=_build_report(),
            exit_code=EXIT_OK,
        )
        monkeypatch.setattr(BuildImageUseCase, "execute", lambda self, request: response)

        result = runner.invoke(app, ["build", "-t", "myapp:1.0", str(clean_context)])

        assert result.exit_code == EXIT_OK
        assert "Build Successful" in result.stdout
        assert "myapp:1.0" in result.stdout
        assert "Security Score: 88/100" in result.stdout
        assert "Tier: B" in result.stdout
        assert "HIGH: " in result.stdout and "1" in result.stdout
        assert "MEDIUM: " in result.stdout and "2" in result.stdout

    def test_hardening_suggestions_are_listed_after_a_successful_build(
        self, clean_context, monkeypatch
    ):
        suggestion = HardeningRule(
            priority=SeverityLevel.HIGH,
            title="Add HEALTHCHECK",
            description="No healthcheck configured",
            current_state="none",
            suggested_fix='HEALTHCHECK CMD ["node", "healthcheck.js"]',
            reason="Orchestrators need a health signal to restart a stuck container",
        )
        response = BuildImageResponse(
            success=True,
            image_tag="myapp:1.0",
            report=_build_report(),
            recommendations=[suggestion],
            exit_code=EXIT_OK,
        )
        monkeypatch.setattr(BuildImageUseCase, "execute", lambda self, request: response)

        result = runner.invoke(app, ["build", "-t", "myapp:1.0", str(clean_context)])

        assert "Hardening Suggestions" in result.stdout
        assert "Add HEALTHCHECK" in result.stdout
        assert "No healthcheck configured" in result.stdout

    def test_failed_build_via_fail_on_threshold_renders_build_failed_panel(
        self, clean_context, monkeypatch
    ):
        """Only the `--fail-on` rejection path sets `image_tag` on a failed
        response; a raw `docker build` failure leaves it unset, which routes
        `_print_table_output` to the validation renderer instead."""
        response = BuildImageResponse(
            success=False,
            image_tag="myapp:1.0",
            error="Vulnerabilities exceed threshold (critical)",
            exit_code=EXIT_POLICY,
        )
        monkeypatch.setattr(BuildImageUseCase, "execute", lambda self, request: response)

        result = runner.invoke(
            app, ["build", "-t", "myapp:1.0", "--fail-on", "critical", str(clean_context)]
        )

        assert result.exit_code == EXIT_POLICY
        assert "Build Failed" in result.stdout
        assert "Vulnerabilities exceed threshold (critical)" in result.stdout

    def test_ci_mode_emits_the_full_report_as_json(self, clean_context, monkeypatch):
        response = BuildImageResponse(
            success=True,
            image_tag="myapp:1.0",
            report=_build_report(),
            exit_code=EXIT_OK,
        )
        monkeypatch.setattr(BuildImageUseCase, "execute", lambda self, request: response)

        result = runner.invoke(
            app, ["build", "-t", "myapp:1.0", "--ci-mode", str(clean_context)]
        )

        assert result.exit_code == EXIT_OK
        payload = json.loads(result.stdout)
        assert payload["status"] == "SUCCESS"
        assert payload["report"]["security_score"] == 88
        assert payload["report"]["scan_results"]["trivy"]["high"] == 1

    def test_html_report_includes_the_vulnerability_scan_table(
        self, clean_context, tmp_path, monkeypatch
    ):
        response = BuildImageResponse(
            success=True,
            image_tag="myapp:1.0",
            report=_build_report(),
            exit_code=EXIT_OK,
        )
        monkeypatch.setattr(BuildImageUseCase, "execute", lambda self, request: response)
        out = tmp_path / "build_report.html"

        result = runner.invoke(
            app, ["build", "-t", "myapp:1.0", "--report", str(out), str(clean_context)]
        )

        assert result.exit_code == EXIT_OK
        html = out.read_text()
        assert "Vulnerability Scan" in html
        assert "No scan was run." not in html
        assert '<td class="high">High</td><td>1</td>' in html
