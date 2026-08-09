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
