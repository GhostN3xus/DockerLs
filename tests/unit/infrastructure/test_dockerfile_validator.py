"""Regras de validação de Dockerfile.

Estes testes existem por causa de uma classe específica de defeito: o
validador dando **PASS numa imagem insegura**. Num scanner de segurança esse
é o pior modo de falha possível — um falso FAIL custa tempo de quem lê, um
falso PASS entrega a imagem em produção com o carimbo da ferramenta.

Quatro regras erravam assim, e as quatro têm caso aqui.
"""

from __future__ import annotations

import pytest

from dockerls.domain.entities.dockerfile_analysis import ValidationStatus
from dockerls.infrastructure.dockerfile_validator import DockerfileValidator


@pytest.fixture
def validate(tmp_path):
    def _validate(content: str, dockerignore: str | None = None):
        (tmp_path / "Dockerfile").write_text(content)
        if dockerignore is not None:
            (tmp_path / ".dockerignore").write_text(dockerignore)
        result = DockerfileValidator().validate(tmp_path)
        return {c.check: c.status for c in result.checks}

    return _validate


class TestNonRootUserAcrossStages:
    def test_user_in_a_build_stage_does_not_protect_the_final_image(self, validate):
        """`USER node` no builder não protege nada: o estágio final sobe como
        root. A regra olhava qualquer USER do arquivo e dava PASS."""
        checks = validate(
            "FROM node:22-alpine AS builder\n"
            "USER node\n"
            "RUN npm ci\n"
            "\n"
            "FROM node:22-alpine\n"
            'CMD ["node", "index.js"]\n'
        )

        assert checks["non_root_user"] == ValidationStatus.FAIL

    def test_user_in_the_final_stage_passes(self, validate):
        checks = validate(
            "FROM node:22-alpine AS builder\n"
            "RUN npm ci\n"
            "\n"
            "FROM node:22-alpine\n"
            "USER node\n"
            'CMD ["node", "index.js"]\n'
        )

        assert checks["non_root_user"] == ValidationStatus.PASS

    def test_final_stage_inherits_user_from_the_stage_it_extends(self, validate):
        """`FROM builder` herda o USER do estágio referenciado."""
        checks = validate(
            'FROM node:22-alpine AS builder\nUSER node\n\nFROM builder\nCMD ["node"]\n'
        )

        assert checks["non_root_user"] == ValidationStatus.PASS

    def test_explicit_user_root_at_the_end_fails(self, validate):
        checks = validate('FROM node:22-alpine\nUSER node\nUSER root\nCMD ["node"]\n')

        assert checks["non_root_user"] == ValidationStatus.FAIL

    def test_user_with_a_group_is_still_non_root(self, validate):
        checks = validate('FROM node:22-alpine\nUSER appuser:appgroup\nCMD ["node"]\n')

        assert checks["non_root_user"] == ValidationStatus.PASS


class TestSecretsInEnv:
    def test_secret_in_a_multi_variable_env_line_is_caught(self, validate):
        """`ENV A=1 B=2` só tinha o primeiro par lido, então um segredo em
        qualquer posição depois da primeira passava batido."""
        checks = validate(
            "FROM node:22-alpine\nUSER node\nENV NODE_ENV=production DOCKER_TOKEN=dckr_pat_leaked\n"
        )

        assert checks["secrets_not_in_env"] == ValidationStatus.FAIL

    def test_legacy_env_form_is_caught(self, validate):
        """A forma antiga `ENV KEY value` não casava com a regex, então essa
        linha nunca era verificada."""
        checks = validate("FROM node:22-alpine\nUSER node\nENV API_KEY abcdef123456\n")

        assert checks["secrets_not_in_env"] == ValidationStatus.FAIL

    def test_quoted_values_do_not_hide_the_key(self, validate):
        checks = validate('FROM node:22-alpine\nUSER node\nENV A="x y" DB_PASSWORD="s3cr3t" B=2\n')

        assert checks["secrets_not_in_env"] == ValidationStatus.FAIL

    def test_benign_env_passes(self, validate):
        checks = validate("FROM node:22-alpine\nUSER node\nENV NODE_ENV=production PORT=8080\n")

        assert checks["secrets_not_in_env"] == ValidationStatus.PASS


class TestMinimalBase:
    def test_a_minimal_builder_does_not_excuse_a_fat_runtime(self, validate):
        """O que vai para produção é o último estágio. Um builder em Alpine
        fazia um runtime em Ubuntu passar como "minimal"."""
        checks = validate(
            "FROM alpine:3.19 AS builder\n"
            "RUN apk add --no-cache build-base\n"
            "\n"
            "FROM ubuntu:22.04\n"
            "USER nobody\n"
        )

        assert checks["minimal_base"] == ValidationStatus.WARN

    def test_minimal_final_stage_passes(self, validate):
        checks = validate("FROM ubuntu:22.04 AS builder\n\nFROM alpine:3.19\nUSER nobody\n")

        assert checks["minimal_base"] == ValidationStatus.PASS


class TestBaseImagePinned:
    def test_stage_reference_without_a_tag_is_not_an_implicit_latest(self, validate):
        """`FROM builder` aponta para um estágio, não para um registry: a
        ausência de tag ali não é `:latest`."""
        checks = validate("FROM node:22-alpine AS builder\n\nFROM builder\nUSER node\n")

        assert checks["base_image_pinned"] == ValidationStatus.PASS

    def test_latest_in_any_stage_fails(self, validate):
        checks = validate("FROM node:latest AS builder\n\nFROM node:22-alpine\nUSER node\n")

        assert checks["base_image_pinned"] == ValidationStatus.FAIL


class TestShellUsage:
    def test_shell_form_cmd_warns(self, validate):
        """Este check devolvia PASS incondicionalmente -- não olhava nada."""
        checks = validate("FROM node:22-alpine\nUSER node\nCMD npm start\n")

        assert checks["shell_usage"] == ValidationStatus.WARN

    def test_exec_form_cmd_passes(self, validate):
        checks = validate('FROM node:22-alpine\nUSER node\nCMD ["npm", "start"]\n')

        assert checks["shell_usage"] == ValidationStatus.PASS

    def test_no_cmd_is_skipped_not_passed(self, validate):
        """SKIP e PASS dizem coisas diferentes: um check que não teve o que
        verificar não pode contar como verificação aprovada."""
        checks = validate("FROM node:22-alpine\nUSER node\n")

        assert checks["shell_usage"] == ValidationStatus.SKIP

    def test_missing_entrypoint_is_skipped_not_absent(self, validate):
        checks = validate("FROM node:22-alpine\nUSER node\n")

        assert checks["entrypoint_exec_form"] == ValidationStatus.SKIP


class TestScratchIsNotAFloatingTag:
    """`FROM scratch` é a imagem vazia embutida no Docker: não é um
    repositório e não tem tag nenhuma para pinar. Tratá-la como "sem tag,
    logo :latest" reprovava com severidade HIGH justamente os Dockerfiles
    mais enxutos que existem -- inclusive o template Go desta ferramenta."""

    def test_scratch_runtime_stage_does_not_fail_the_pin_rule(self, validate):
        checks = validate(
            "FROM golang:1.23-alpine AS builder\n"
            "RUN go build -o app .\n"
            "\n"
            "FROM scratch\n"
            "COPY --from=builder /app/app /app\n"
            "USER 65534:65534\n"
            'ENTRYPOINT ["/app"]\n'
        )

        assert checks["base_image_pinned"] == ValidationStatus.PASS
        assert checks["non_root_user"] == ValidationStatus.PASS

    def test_scratch_with_a_platform_flag_is_still_scratch(self, validate):
        checks = validate("FROM --platform=$BUILDPLATFORM scratch\nUSER 65534\n")

        assert checks["base_image_pinned"] == ValidationStatus.PASS

    def test_an_actually_untagged_image_still_fails(self, validate):
        checks = validate("FROM ubuntu\nUSER app\n")

        assert checks["base_image_pinned"] == ValidationStatus.FAIL


class TestNumericRootUser:
    """`USER 0` e `USER 0:0` são root tanto quanto `USER root`, e passavam:
    a checagem só comparava com a string "root". Um falso PASS em
    non_root_user é o pior desfecho possível desta regra."""

    @pytest.mark.parametrize("directive", ["USER 0", "USER 0:0", "USER root", "USER root:root"])
    def test_root_by_any_spelling_fails(self, validate, directive):
        checks = validate(f"FROM node:22-alpine\n{directive}\n")

        assert checks["non_root_user"] == ValidationStatus.FAIL

    @pytest.mark.parametrize("directive", ["USER 1000", "USER 65534:65534", "USER appuser"])
    def test_a_real_non_root_user_still_passes(self, validate, directive):
        checks = validate(f"FROM node:22-alpine\n{directive}\n")

        assert checks["non_root_user"] == ValidationStatus.PASS


class TestTrailingLineContinuation:
    """Um arquivo terminado em barra invertida deixava a diretiva pendente
    no buffer do parser, e ela sumia sem ser verificada."""

    def test_a_final_unterminated_run_is_still_inspected(self, validate):
        checks = validate("FROM node:22-alpine\nUSER node\nRUN sudo apt-get update && \\")

        assert checks["no_sudo"] == ValidationStatus.FAIL

    def test_a_final_unterminated_env_still_reports_its_secret(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM node:22-alpine\nUSER node\nENV API_KEY=abc \\")
        result = DockerfileValidator().validate(tmp_path)

        secret_check = next(c for c in result.checks if c.check == "secrets_not_in_env")
        assert secret_check.status == ValidationStatus.FAIL
        assert "API_KEY" in secret_check.message


class TestUnreadableDockerignore:
    def test_it_is_reported_as_skip_not_as_a_crash(self, tmp_path, monkeypatch):
        """Um `.dockerignore` presente mas ilegível derrubava a validação
        inteira por causa de um check opcional."""
        (tmp_path / "Dockerfile").write_text("FROM node:22-alpine\nUSER node\n")
        (tmp_path / ".dockerignore").write_text(".git\n")

        real_read_text = type(tmp_path).read_text

        def boom(self, *args, **kwargs):
            if self.name == ".dockerignore":
                raise PermissionError("denied")
            return real_read_text(self, *args, **kwargs)

        monkeypatch.setattr(type(tmp_path), "read_text", boom)

        result = DockerfileValidator().validate(tmp_path)
        check = next(c for c in result.checks if c.check == "dockerignore_complete")
        assert check.status == ValidationStatus.SKIP
