"""The parser is the floor every security rule stands on.

A rule that looks for `--mount=type=secret` and never sees it because the
parser dropped the flag reports a clean Dockerfile that is not clean, so
these tests pin the shapes that are easy to lose: continuations, heredocs,
flags, stage scoping and ARG substitution.
"""

import pytest

from dockerls.infrastructure.dockerfile.parser import (
    DockerfileParseError,
    find_dockerfile,
    parse_dockerfile,
    parse_dockerfile_text,
)


class TestBasicParsing:
    def test_parses_keyword_value_and_line_number(self):
        parsed = parse_dockerfile_text("FROM alpine:3.19\nUSER appuser\n")
        assert [i.keyword for i in parsed.instructions] == ["FROM", "USER"]
        assert parsed.instructions[1].value == "appuser"
        assert parsed.instructions[1].line == 2

    def test_skips_comments_and_blank_lines(self):
        parsed = parse_dockerfile_text("# a comment\n\nFROM alpine:3.19\n\n# another\n")
        assert len(parsed.instructions) == 1

    def test_lowercase_instructions_are_normalised(self):
        parsed = parse_dockerfile_text("from alpine:3.19\nuser appuser\n")
        assert [i.keyword for i in parsed.instructions] == ["FROM", "USER"]

    def test_unknown_instruction_is_recorded_not_raised(self):
        parsed = parse_dockerfile_text("FROM alpine:3.19\nFROOM nonsense\n")
        assert len(parsed.instructions) == 1
        assert "FROOM" in parsed.parse_errors[0]

    def test_empty_file_raises_on_disk(self, tmp_path):
        path = tmp_path / "Dockerfile"
        path.write_text("# only a comment\n")
        with pytest.raises(DockerfileParseError):
            parse_dockerfile(path)


class TestLineContinuations:
    def test_backslash_continuation_becomes_one_instruction(self):
        text = "FROM alpine:3.19\nRUN apk add --no-cache curl \\\n    && rm -rf /tmp/*\n"
        parsed = parse_dockerfile_text(text)
        run = parsed.instructions_of("RUN")[0]
        assert "apk add" in run.value
        assert "rm -rf /tmp/*" in run.value
        assert run.line == 2

    def test_comment_inside_a_continuation_is_dropped(self):
        text = "FROM alpine:3.19\nRUN echo one \\\n# explanatory comment\n    && echo two\n"
        run = parse_dockerfile_text(text).instructions_of("RUN")[0]
        assert "explanatory" not in run.value
        assert "echo two" in run.value

    def test_backtick_escape_directive_is_honoured(self):
        text = "# escape=`\nFROM alpine:3.19\nRUN echo one `\n    && echo two\n"
        parsed = parse_dockerfile_text(text)
        run = parsed.instructions_of("RUN")[0]
        assert "echo two" in run.value

    def test_heredoc_body_belongs_to_its_instruction(self):
        text = "FROM alpine:3.19\nRUN <<EOF\napk add --no-cache curl\nEOF\nUSER appuser\n"
        parsed = parse_dockerfile_text(text)
        run = parsed.instructions_of("RUN")[0]
        assert "apk add --no-cache curl" in run.value
        # The heredoc must not swallow the instruction that follows it.
        assert parsed.instructions_of("USER")


class TestFlags:
    def test_copy_from_flag_is_parsed_out_of_the_value(self):
        parsed = parse_dockerfile_text(
            "FROM alpine:3.19 AS builder\nFROM alpine:3.19\n"
            "COPY --from=builder --chown=app:app /out /app\n"
        )
        copy = parsed.instructions_of("COPY")[0]
        assert copy.flags["from"] == "builder"
        assert copy.flags["chown"] == "app:app"
        assert copy.value == "/out /app"

    def test_run_mount_secret_flag_survives(self):
        parsed = parse_dockerfile_text(
            "FROM alpine:3.19\nRUN --mount=type=secret,id=tok cat /run/secrets/tok\n"
        )
        run = parsed.instructions_of("RUN")[0]
        assert run.flags["mount"] == "type=secret,id=tok"

    def test_command_flags_are_not_mistaken_for_instruction_flags(self):
        """`--no-install-recommends` belongs to apt, not to RUN. Consuming
        it would make the apt rule permanently unsatisfiable."""
        parsed = parse_dockerfile_text(
            "FROM debian:12\nRUN apt-get install -y --no-install-recommends curl\n"
        )
        run = parsed.instructions_of("RUN")[0]
        assert "--no-install-recommends" in run.value
        assert run.flags == {}


class TestStages:
    def test_stage_names_and_indices(self):
        parsed = parse_dockerfile_text(
            "FROM golang:1.23-alpine AS builder\nRUN go build\n"
            "FROM scratch\nCOPY --from=builder /app /app\n"
        )
        assert parsed.stage_count == 2
        assert parsed.is_multi_stage
        assert parsed.stages[0].name == "builder"
        assert parsed.final_stage.is_scratch

    def test_final_stage_instructions_exclude_builder_stage(self):
        parsed = parse_dockerfile_text(
            "FROM alpine:3.19 AS builder\nUSER root\nFROM alpine:3.19\nUSER appuser\n"
        )
        users = parsed.final_stage_instructions("USER")
        assert [u.value for u in users] == ["appuser"]

    def test_base_image_is_the_final_stage(self):
        parsed = parse_dockerfile_text("FROM golang:1.23 AS b\nFROM alpine:3.19\n")
        assert parsed.base_image == "alpine:3.19"


class TestBaseReferenceParsing:
    @pytest.mark.parametrize(
        ("reference", "name", "tag"),
        [
            ("node:22-alpine", "node", "22-alpine"),
            ("node", "node", ""),
            ("ghcr.io/org/app:1.2.3", "ghcr.io/org/app", "1.2.3"),
            ("registry.internal:5000/team/app", "registry.internal:5000/team/app", ""),
            ("registry.internal:5000/team/app:v1", "registry.internal:5000/team/app", "v1"),
            ("cgr.dev/chainguard/node:latest", "cgr.dev/chainguard/node", "latest"),
        ],
    )
    def test_name_and_tag_are_split_correctly(self, reference, name, tag):
        stage = parse_dockerfile_text(f"FROM {reference}\n").stages[0]
        assert stage.base_name == name
        assert stage.base_tag == tag

    def test_digest_reference_is_recognised(self):
        digest = "a" * 64
        stage = parse_dockerfile_text(f"FROM node@sha256:{digest}\n").stages[0]
        assert stage.has_digest
        assert stage.base_name == "node"


class TestArgResolution:
    def test_global_args_are_substituted_into_from(self):
        parsed = parse_dockerfile_text(
            "ARG NODE_VERSION=22.11.0\nARG ALPINE_VERSION=3.19\n"
            "FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION}\n"
        )
        assert parsed.stages[0].base_image == "node:22.11.0-alpine3.19"
        assert parsed.stages[0].base_tag == "22.11.0-alpine3.19"

    def test_bare_dollar_reference_is_substituted(self):
        parsed = parse_dockerfile_text("ARG TAG=3.19\nFROM alpine:$TAG\n")
        assert parsed.stages[0].base_image == "alpine:3.19"

    def test_unknown_arg_is_left_alone(self):
        parsed = parse_dockerfile_text("FROM alpine:${MYSTERY}\n")
        assert "${MYSTERY}" in parsed.stages[0].base_image

    def test_args_after_the_first_from_are_not_global(self):
        """Docker only allows *global* ARGs in a FROM line, so an ARG
        declared inside a stage must not silently resolve one."""
        parsed = parse_dockerfile_text("FROM alpine:3.19\nARG TAG=1.0\nFROM busybox:$TAG\n")
        assert parsed.stages[1].base_image == "busybox:$TAG"


class TestExecForm:
    @pytest.mark.parametrize(
        ("value", "exec_form"),
        [
            ('ENTRYPOINT ["node", "app.js"]', True),
            ("ENTRYPOINT node app.js", False),
            ('CMD ["sh"]', True),
        ],
    )
    def test_exec_form_detection(self, value, exec_form):
        parsed = parse_dockerfile_text(f"FROM alpine:3.19\n{value}\n")
        assert parsed.instructions[1].is_exec_form is exec_form


class TestFindDockerfile:
    def test_finds_dockerfile_in_a_directory(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n")
        assert find_dockerfile(tmp_path) == tmp_path / "Dockerfile"

    def test_accepts_a_direct_file_path(self, tmp_path):
        path = tmp_path / "Dockerfile.prod"
        path.write_text("FROM alpine:3.19\n")
        assert find_dockerfile(path) == path

    def test_explicit_file_wins(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n")
        explicit = tmp_path / "Dockerfile.hardened"
        explicit.write_text("FROM alpine:3.19\n")
        assert find_dockerfile(tmp_path, explicit) == explicit

    def test_missing_dockerfile_raises(self, tmp_path):
        with pytest.raises(DockerfileParseError, match="No Dockerfile"):
            find_dockerfile(tmp_path)

    def test_missing_explicit_file_raises(self, tmp_path):
        with pytest.raises(DockerfileParseError, match="not found"):
            find_dockerfile(tmp_path, tmp_path / "nope")
