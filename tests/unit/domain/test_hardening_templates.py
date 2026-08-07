"""The bundled templates are the tool's own advice, so they are held to it.

A hardened template that does not itself clear the rule set is the worst
possible bug in this feature: it teaches the exact habits the validator is
meant to stop, with the tool's name on it.
"""

import pytest

from dockerls.application.services.dockerfile_validator import OwaspDockerfileValidator
from dockerls.application.use_cases.generate_hardened_dockerfile import (
    DEFAULT_OUTPUT_NAME,
    GenerateHardenedDockerfileUseCase,
    TemplateGenerationError,
)
from dockerls.domain.entities.build_validation import CheckStatus, HardeningLevel
from dockerls.infrastructure.dockerfile.parser import parse_dockerfile_text
from dockerls.infrastructure.templates.loader import (
    TEMPLATES,
    available_templates,
    get_template,
)

TEMPLATE_NAMES = sorted(TEMPLATES)


def _generate(tmp_path, base):
    GenerateHardenedDockerfileUseCase().execute(tmp_path, base=base)
    return tmp_path / DEFAULT_OUTPUT_NAME


@pytest.mark.parametrize("name", TEMPLATE_NAMES)
class TestEveryTemplateIsHardened:
    def test_clears_the_whole_rule_set(self, tmp_path, name):
        path = _generate(tmp_path, name)
        result = OwaspDockerfileValidator().validate(path, tmp_path)
        offenders = [(c.check, c.status.value, c.message) for c in result.checks if c.failed]
        assert offenders == [], f"{name} template has findings: {offenders}"

    def test_passes_even_at_the_strictest_level(self, tmp_path, name):
        path = _generate(tmp_path, name)
        validator = OwaspDockerfileValidator(hardening_level=HardeningLevel.STRICT)
        assert not validator.validate(path, tmp_path).has_blocking_findings

    def test_runs_as_a_non_root_user(self, tmp_path, name):
        parsed = parse_dockerfile_text(get_template(name).read())
        users = parsed.final_stage_instructions("USER")
        assert users, f"{name} template has no USER directive"
        assert users[-1].value.strip().lower() not in ("root", "0")

    def test_declares_a_healthcheck(self, tmp_path, name):
        parsed = parse_dockerfile_text(get_template(name).read())
        assert parsed.final_stage_instructions("HEALTHCHECK")

    def test_is_multi_stage(self, tmp_path, name):
        assert parse_dockerfile_text(get_template(name).read()).is_multi_stage

    def test_pins_every_base_image(self, tmp_path, name):
        parsed = parse_dockerfile_text(get_template(name).read())
        for stage in parsed.stages:
            if stage.is_scratch:
                continue
            assert stage.base_tag and stage.base_tag != "latest", (
                f"{name}: stage {stage.index} base {stage.base_image} is unpinned"
            )

    def test_uses_exec_form(self, tmp_path, name):
        parsed = parse_dockerfile_text(get_template(name).read())
        for instruction in parsed.final_stage_instructions("ENTRYPOINT", "CMD"):
            assert instruction.is_exec_form


class TestTemplateLoader:
    def test_every_listed_template_is_readable(self):
        for template in available_templates():
            assert template.read().startswith("#")

    @pytest.mark.parametrize(
        ("alias", "expected"), [("nodejs", "node"), ("golang", "go"), ("PY", "python")]
    )
    def test_common_aliases_resolve(self, alias, expected):
        assert get_template(alias).name == expected

    def test_unknown_template_lists_the_alternatives(self):
        with pytest.raises(ValueError, match="Available:"):
            get_template("cobol")


class TestGeneration:
    def test_detects_the_project_type_from_its_files(self, tmp_path):
        (tmp_path / "go.mod").write_text("module x\n")
        result = GenerateHardenedDockerfileUseCase().execute(tmp_path)
        assert result.template == "go"
        assert result.detected_from == "go"

    def test_undetectable_project_asks_for_an_explicit_base(self, tmp_path):
        with pytest.raises(TemplateGenerationError, match="--base"):
            GenerateHardenedDockerfileUseCase().execute(tmp_path)

    def test_never_silently_overwrites(self, tmp_path):
        target = tmp_path / DEFAULT_OUTPUT_NAME
        target.write_text("FROM scratch\n")
        with pytest.raises(TemplateGenerationError, match="--force"):
            GenerateHardenedDockerfileUseCase().execute(tmp_path, base="node")
        assert target.read_text() == "FROM scratch\n"

    def test_force_replaces_and_says_so(self, tmp_path):
        (tmp_path / DEFAULT_OUTPUT_NAME).write_text("FROM scratch\n")
        result = GenerateHardenedDockerfileUseCase().execute(tmp_path, base="node", force=True)
        assert result.overwritten

    def test_writes_a_dockerignore_so_the_copy_is_safe(self, tmp_path):
        result = GenerateHardenedDockerfileUseCase().execute(tmp_path, base="node")
        ignore = tmp_path / ".dockerignore"
        assert ignore.exists()
        assert result.dockerignore_path == str(ignore)
        assert ".git" in ignore.read_text()

    def test_existing_dockerignore_is_left_alone(self, tmp_path):
        (tmp_path / ".dockerignore").write_text("custom\n")
        result = GenerateHardenedDockerfileUseCase().execute(tmp_path, base="node")
        assert (tmp_path / ".dockerignore").read_text() == "custom\n"
        assert result.dockerignore_path == ""

    def test_generation_reports_its_own_validation(self, tmp_path):
        use_case = GenerateHardenedDockerfileUseCase(validator=OwaspDockerfileValidator())
        result = use_case.execute(tmp_path, base="python")
        assert result.checks_total > 0
        assert result.checks_passed == result.checks_total

    def test_refuses_a_non_directory(self, tmp_path):
        target = tmp_path / "file.txt"
        target.write_text("x")
        with pytest.raises(TemplateGenerationError, match="Not a directory"):
            GenerateHardenedDockerfileUseCase().execute(target, base="node")

    def test_output_path_is_honoured(self, tmp_path):
        target = tmp_path / "Dockerfile.prod"
        GenerateHardenedDockerfileUseCase().execute(tmp_path, base="go", output=target)
        assert target.exists()
        assert OwaspDockerfileValidator().validate(target, tmp_path).checks[0].status in (
            CheckStatus.PASS,
            CheckStatus.SKIP,
        )
