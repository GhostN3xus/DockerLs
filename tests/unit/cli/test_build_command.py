"""End-to-end behaviour of `dockerls build` and `dockerls templates`.

Nothing here touches a Docker daemon: `--validate-only` and
`--suggest-hardening` exercise the whole CLI path -- flag parsing, policy
loading, rendering, exit codes -- without one, which is also how they behave
for a user with no daemon running.
"""

import json

import pytest
from typer.testing import CliRunner

from dockerls.cli.app import app
from dockerls.cli.commands.build import _pairs, _secrets

runner = CliRunner()

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_WARNINGS = 2

CLEAN = """\
FROM alpine:3.19 AS builder
RUN apk add --no-cache gcc

FROM alpine:3.19
LABEL maintainer="team@example.com"
LABEL security.cve-contact="security@example.com"
RUN addgroup -g 1000 g && adduser -D -u 1000 -G g appuser
COPY --from=builder --chown=appuser:g /app /app
USER appuser
HEALTHCHECK --interval=30s CMD ["/app/health"]
ENTRYPOINT ["/app/server"]
"""

LEAKY = 'FROM alpine:3.19\nENV NPM_TOKEN=real\nUSER app\nENTRYPOINT ["/a"]\n'


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A build context with a Dockerfile, isolated from the developer's own
    config so a real ~/.config/dockerls cannot change the result."""
    (tmp_path / "Dockerfile").write_text(CLEAN)
    (tmp_path / ".dockerignore").write_text(".git\n.env\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    return tmp_path


def _run(*args):
    return runner.invoke(app, list(args))


class TestValidateOnly:
    def test_a_hardened_dockerfile_passes(self, project):
        result = _run("build", str(project), "--validate-only")
        assert result.exit_code == EXIT_OK
        assert "PASS" in result.stdout

    def test_a_leaked_credential_fails_the_run(self, project):
        (project / "Dockerfile").write_text(LEAKY)
        result = _run("build", str(project), "--validate-only")
        assert result.exit_code == EXIT_FAILED
        assert "secrets_not_in_env" in result.stdout

    def test_an_advisory_finding_exits_two_not_one(self, project):
        """Two isn't a detail: it is how a pipeline distinguishes "look at
        this" from "stop"."""
        (project / "Dockerfile").write_text('FROM alpine:3.19\nUSER app\nENTRYPOINT ["/a"]\n')
        result = _run("build", str(project), "--validate-only")
        assert result.exit_code == EXIT_WARNINGS

    def test_findings_come_with_their_fix(self, project):
        (project / "Dockerfile").write_text(LEAKY)
        result = _run("build", str(project), "--validate-only")
        assert "How to fix" in result.stdout
        assert "--mount=type=secret" in result.stdout

    def test_no_tag_is_required_to_validate(self, project):
        assert _run("build", str(project), "--validate-only").exit_code == EXIT_OK

    def test_a_tag_is_required_to_build(self, project):
        result = _run("build", str(project))
        assert result.exit_code == EXIT_FAILED
        assert "--tag is required" in result.stdout

    def test_a_missing_dockerfile_is_explained(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
        result = _run("build", str(tmp_path), "--validate-only")
        assert result.exit_code == EXIT_FAILED
        assert "No Dockerfile" in result.stdout

    def test_an_explicit_file_is_honoured(self, project):
        target = project / "Dockerfile.prod"
        target.write_text(LEAKY)
        result = _run("build", str(project), "--file", str(target), "--validate-only")
        assert result.exit_code == EXIT_FAILED


class TestCiMode:
    def _payload(self, result):
        return json.loads(result.stdout)

    def test_emits_only_json(self, project):
        result = _run("build", str(project), "--validate-only", "--ci-mode")
        payload = self._payload(result)
        assert payload["status"] == "OK"
        assert payload["security_tier"] in ("S", "A", "B", "C")

    def test_a_failure_names_what_tripped(self, project):
        (project / "Dockerfile").write_text(LEAKY)
        result = _run("build", str(project), "--validate-only", "--ci-mode")
        assert result.exit_code == EXIT_FAILED
        payload = self._payload(result)
        assert payload["status"] == "FAILED"
        assert "secrets_not_in_env" in payload["reason"]

    def test_every_rule_appears_in_the_payload(self, project):
        payload = self._payload(_run("build", str(project), "--validate-only", "--ci-mode"))
        statuses = {c["status"] for c in payload["validation"]["checks"]}
        assert statuses <= {"PASS", "WARN", "FAIL", "SKIP"}
        assert len(payload["validation"]["checks"]) >= 15

    def test_ci_mode_always_writes_a_sarif_file(self, project):
        """It is the artefact the GitHub security tab consumes, so it must
        not depend on the user remembering --format sarif."""
        _run("build", str(project), "--validate-only", "--ci-mode")
        assert list((project / ".dockerls" / "reports").glob("*.sarif"))

    def test_a_configuration_error_is_json_too(self, project):
        result = _run("build", str(project), "--ci-mode", "--hardening-level", "paranoid")
        assert result.exit_code == EXIT_FAILED
        assert json.loads(result.stdout)["status"] == "FAILED"


class TestSuggestHardening:
    def test_suggests_a_better_base_image(self, project):
        (project / "Dockerfile").write_text('FROM node:22\nUSER app\nENTRYPOINT ["/a"]\n')
        result = _run("build", str(project), "--suggest-hardening", "--ci-mode")
        rules = {r["rule_id"] for r in json.loads(result.stdout)["recommendations"]}
        assert "base_image_upgrade" in rules

    def test_suggestions_are_shown_in_the_human_output(self, project):
        (project / "Dockerfile").write_text('FROM node:22\nUSER app\nENTRYPOINT ["/a"]\n')
        result = _run("build", str(project), "--suggest-hardening")
        assert "Recommendations" in result.stdout


class TestHardeningLevels:
    def test_relaxed_tolerates_what_standard_blocks(self, project):
        (project / "Dockerfile").write_text('FROM node:latest\nUSER app\nENTRYPOINT ["/a"]\n')
        strict = _run("build", str(project), "--validate-only")
        relaxed = _run("build", str(project), "--validate-only", "--hardening-level", "relaxed")
        assert strict.exit_code == EXIT_FAILED
        assert relaxed.exit_code != EXIT_FAILED

    def test_an_unknown_level_lists_the_valid_ones(self, project):
        result = _run("build", str(project), "--validate-only", "--hardening-level", "paranoid")
        assert result.exit_code == EXIT_FAILED
        assert "strict" in result.stdout


class TestPolicyFile:
    def test_the_project_policy_is_picked_up_automatically(self, project):
        (project / ".dockerls-hardening.yaml").write_text(
            "validation:\n  hardening_level: relaxed\n"
        )
        (project / "Dockerfile").write_text('FROM node:latest\nUSER app\nENTRYPOINT ["/a"]\n')
        assert _run("build", str(project), "--validate-only").exit_code != EXIT_FAILED

    def test_the_command_line_overrides_the_policy(self, project):
        (project / ".dockerls-hardening.yaml").write_text(
            "validation:\n  hardening_level: relaxed\n"
        )
        (project / "Dockerfile").write_text('FROM node:latest\nUSER app\nENTRYPOINT ["/a"]\n')
        result = _run("build", str(project), "--validate-only", "--hardening-level", "standard")
        assert result.exit_code == EXIT_FAILED

    def test_a_waived_rule_still_appears_in_the_report(self, project):
        (project / ".dockerls-hardening.yaml").write_text(
            "validation:\n  hardening_level: standard\n  skip_rules: [base_image_pinned]\n"
        )
        (project / "Dockerfile").write_text('FROM node:latest\nUSER app\nENTRYPOINT ["/a"]\n')
        result = _run("build", str(project), "--validate-only", "--ci-mode")
        checks = {
            c["check"]: c["status"] for c in json.loads(result.stdout)["validation"]["checks"]
        }
        assert checks["base_image_pinned"] == "SKIP"
        assert result.exit_code != EXIT_FAILED

    def test_a_broken_policy_stops_the_run(self, project):
        (project / ".dockerls-hardening.yaml").write_text("scanning:\n  fail_on: whenever\n")
        result = _run("build", str(project), "--validate-only")
        assert result.exit_code == EXIT_FAILED
        assert "fail_on" in result.stdout

    def test_a_named_policy_file_that_does_not_exist_is_an_error(self, project):
        result = _run("build", str(project), "--validate-only", "--config", "missing.yaml")
        assert result.exit_code == EXIT_FAILED
        assert "not found" in result.stdout

    def test_batch_without_projects_says_what_is_missing(self, project):
        (project / ".dockerls-hardening.yaml").write_text("scanning:\n  fail_on: high\n")
        result = _run("build", str(project), "--validate-only", "--batch")
        assert result.exit_code == EXIT_FAILED
        assert "projects:" in result.stdout


class TestReportOutput:
    def test_report_extension_selects_the_format(self, project, tmp_path):
        target = tmp_path / "out.html"
        _run("build", str(project), "--validate-only", "--report", str(target))
        assert target.read_text().startswith("<!DOCTYPE html>")

    def test_repeatable_format_flag_writes_each_one(self, project):
        _run(
            "build",
            str(project),
            "--validate-only",
            "--format",
            "json",
            "--format",
            "markdown",
        )
        written = list((project / ".dockerls" / "reports").iterdir())
        assert {p.suffix for p in written} == {".json", ".md"}


class TestArgumentParsing:
    def test_key_value_pairs(self):
        assert _pairs(["A=1", "B=2"], "", "--build-arg") == {"A": "1", "B": "2"}

    def test_a_value_may_contain_equals_signs(self):
        assert _pairs(["URL=a=b=c"], "", "--build-arg") == {"URL": "a=b=c"}

    def test_json_form_is_accepted(self):
        assert _pairs([], '{"A": "1"}', "--build-arg") == {"A": "1"}

    def test_explicit_pairs_win_over_the_json_form(self):
        assert _pairs(["A=explicit"], '{"A": "json"}', "--build-arg") == {"A": "explicit"}

    def test_a_pair_without_an_equals_sign_is_rejected(self):
        with pytest.raises(ValueError, match="KEY=VALUE"):
            _pairs(["JUSTAKEY"], "", "--build-arg")

    def test_malformed_json_is_rejected(self):
        with pytest.raises(ValueError, match="not valid JSON"):
            _pairs([], "{not json", "--build-arg")

    def test_a_json_array_is_rejected(self):
        with pytest.raises(ValueError, match="JSON object"):
            _pairs([], '["a"]', "--build-arg")

    def test_secret_from_an_environment_variable(self):
        [secret] = _secrets(["id=npm,env=NPM_TOKEN"])
        assert secret.secret_id == "npm"
        assert secret.env == "NPM_TOKEN"

    def test_secret_from_a_file(self):
        [secret] = _secrets(["id=npm,src=/run/token"])
        assert secret.file == "/run/token"

    def test_a_secret_without_an_id_is_rejected(self):
        with pytest.raises(ValueError, match="id="):
            _secrets(["env=NPM_TOKEN"])

    def test_a_secret_without_a_source_is_rejected(self):
        with pytest.raises(ValueError, match="env= or src="):
            _secrets(["id=npm"])

    def test_a_bad_build_arg_stops_the_run(self, project):
        result = _run("build", str(project), "--validate-only", "--build-arg", "NOEQUALS")
        assert result.exit_code == EXIT_FAILED


class TestTemplatesCommand:
    def test_listing_shows_every_template(self):
        result = _run("templates", "list")
        assert result.exit_code == EXIT_OK
        for name in ("node", "python", "go", "java"):
            assert name in result.stdout

    def test_bare_templates_lists_them_too(self):
        assert "node" in _run("templates").stdout

    def test_show_prints_a_dockerfile(self):
        result = _run("templates", "show", "go", "--raw")
        assert result.exit_code == EXIT_OK
        assert "FROM scratch" in result.stdout

    def test_show_rejects_an_unknown_template(self):
        result = _run("templates", "show", "cobol")
        assert result.exit_code == EXIT_FAILED
        assert "Available:" in result.stdout

    def test_generate_writes_a_file_that_passes_validation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
        result = _run("templates", "generate", str(tmp_path), "--base", "python")
        assert result.exit_code == EXIT_OK
        target = tmp_path / "Dockerfile.hardened"
        assert target.exists()
        validated = _run("build", str(tmp_path), "--file", str(target), "--validate-only")
        assert validated.exit_code == EXIT_OK

    def test_generate_refuses_to_clobber(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
        (tmp_path / "Dockerfile.hardened").write_text("FROM scratch\n")
        result = _run("templates", "generate", str(tmp_path), "--base", "node")
        assert result.exit_code == EXIT_FAILED
        assert "--force" in result.stdout

    def test_generate_detects_the_project_type(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
        (tmp_path / "package.json").write_text("{}")
        result = _run("templates", "generate", str(tmp_path))
        assert "node" in result.stdout


class TestHelp:
    def test_build_is_registered(self):
        assert "build" in _run("--help").stdout

    def test_build_help_documents_the_workflow(self):
        out = _run("build", "--help").stdout
        for flag in ("--validate-only", "--fail-on", "--ci-mode", "--hardened", "--push"):
            assert flag in out


class TestHardenedTemplateBuild:
    def test_hardened_swaps_in_the_bundled_template(self, project):
        """The generated file stays on disk: a build nobody can inspect
        afterwards is a build nobody can review."""
        (project / "Dockerfile").write_text(LEAKY)
        result = _run("build", str(project), "--hardened", "--base", "go", "--validate-only")
        assert result.exit_code == EXIT_OK
        assert (project / "Dockerfile.hardened").exists()
        assert "FROM scratch" in (project / "Dockerfile.hardened").read_text()

    def test_an_unknown_template_stops_the_run(self, project):
        result = _run("build", str(project), "--hardened", "--base", "cobol", "--validate-only")
        assert result.exit_code == EXIT_FAILED
        assert "Available:" in result.stdout


class TestBatch:
    POLICY = """\
validation:
  hardening_level: standard
projects:
  - name: api
    context: ./api
    tag: "api:1.0"
  - name: web
    context: ./web
    tag: "web:1.0"
"""

    def _services(self, project, web_dockerfile=CLEAN):
        for name, text in (("api", CLEAN), ("web", web_dockerfile)):
            service = project / name
            service.mkdir()
            (service / "Dockerfile").write_text(text)
            (service / ".dockerignore").write_text(".git\n.env\n")
        (project / ".dockerls-hardening.yaml").write_text(self.POLICY)

    def test_every_project_is_validated(self, project):
        self._services(project)
        result = _run("build", str(project), "--batch", "--validate-only", "--ci-mode")
        payload = json.loads(result.stdout)
        assert [b["dockerfile_path"].split("/")[-2] for b in payload["builds"]] == ["api", "web"]
        assert result.exit_code == EXIT_OK

    def test_one_bad_project_fails_the_whole_batch(self, project):
        """A pipeline building five images must stop if any one of them
        failed, so the worst outcome decides the exit code."""
        self._services(project, web_dockerfile=LEAKY)
        result = _run("build", str(project), "--batch", "--validate-only")
        assert result.exit_code == EXIT_FAILED


class TestInteractiveWizard:
    def test_the_wizard_collects_the_missing_answers(self, project):
        answers = "\n".join(["go", "y", "myapp:1.0", "n", "json", "n"]) + "\n"
        result = runner.invoke(
            app, ["build", str(project), "--interactive", "--validate-only"], input=answers
        )
        assert "Application type" in result.stdout
        assert (project / "Dockerfile.hardened").exists()

    def test_flags_already_given_are_not_re_asked(self, project):
        answers = "\n".join(["n", "json", "n"]) + "\n"
        result = runner.invoke(
            app,
            [
                "build",
                str(project),
                "--interactive",
                "--base",
                "go",
                "--hardened",
                "--tag",
                "myapp:1.0",
                "--validate-only",
            ],
            input=answers,
        )
        assert "Application type" not in result.stdout
        assert "Image tag" not in result.stdout

    def test_the_wizard_is_skipped_in_ci_mode(self, project):
        """A prompt in CI is a hung pipeline."""
        result = _run("build", str(project), "--interactive", "--ci-mode", "--validate-only")
        assert result.exit_code == EXIT_OK
        assert json.loads(result.stdout)["status"] == "OK"
