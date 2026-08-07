"""Suggestions are advice, and advice that is wrong or noisy gets ignored.

Two properties matter more than the individual rules: a suggestion never
blocks anything, and the same Dockerfile always produces the same list --
otherwise two build reports cannot be diffed.
"""

import pytest

from dockerls.application.services.hardening_suggester import HardeningSuggester
from dockerls.domain.entities.build_validation import (
    CheckStatus,
    ValidationCheck,
    ValidationResult,
)
from dockerls.domain.entities.hardening_rule import HardeningRule, Priority
from dockerls.domain.entities.vulnerability import Severity
from dockerls.infrastructure.dockerfile.parser import parse_dockerfile_text


def _suggest(text, validation=None):
    parsed = parse_dockerfile_text(text)
    return HardeningSuggester().suggest(validation or ValidationResult(), parsed)


def _ids(suggestions):
    return [s.rule_id for s in suggestions]


class TestFromFindings:
    def test_each_finding_becomes_an_actionable_suggestion(self):
        validation = ValidationResult(
            checks=[
                ValidationCheck(
                    check="non_root_user",
                    title="Runs as a non-root user",
                    status=CheckStatus.FAIL,
                    severity=Severity.HIGH,
                    message="No USER directive",
                    line=2,
                    fix="USER appuser",
                )
            ]
        )
        [suggestion] = [
            s
            for s in _suggest("FROM alpine:3.19\nRUN x\n", validation)
            if s.rule_id == "non_root_user"
        ]
        assert suggestion.priority is Priority.HIGH
        assert suggestion.suggested == "USER appuser"
        assert suggestion.current == "RUN x"

    def test_passing_checks_produce_no_advice(self):
        validation = ValidationResult(
            checks=[ValidationCheck(check="no_sudo", status=CheckStatus.PASS)]
        )
        assert "no_sudo" not in _ids(_suggest("FROM alpine:3.19\n", validation))

    def test_skipped_checks_produce_no_advice(self):
        validation = ValidationResult(
            checks=[ValidationCheck(check="dockerignore_present", status=CheckStatus.SKIP)]
        )
        assert "dockerignore_present" not in _ids(_suggest("FROM alpine:3.19\n", validation))

    @pytest.mark.parametrize(
        ("severity", "priority"),
        [
            (Severity.CRITICAL, Priority.HIGH),
            (Severity.HIGH, Priority.HIGH),
            (Severity.MEDIUM, Priority.MEDIUM),
            (Severity.LOW, Priority.LOW),
        ],
    )
    def test_priority_mirrors_severity(self, severity, priority):
        rule = HardeningRule.from_severity(severity, rule_id="r", title="t")
        assert rule.priority is priority


class TestBaseImageUpgrades:
    @pytest.mark.parametrize(
        ("base", "vendor"),
        [
            ("node:22", "chainguard"),
            ("python:3.12", "chainguard"),
            ("ubuntu:24.04", "chainguard"),
            ("debian:12", "distroless"),
            ("golang:1.23", "distroless"),
        ],
    )
    def test_common_bases_get_a_hardened_alternative(self, base, vendor):
        [upgrade] = [s for s in _suggest(f"FROM {base}\n") if s.rule_id == "base_image_upgrade"]
        assert vendor in upgrade.suggested
        assert upgrade.current == base
        assert upgrade.reason

    def test_an_already_hardened_base_is_not_told_to_harden(self):
        """Repeating advice the user already took is how a report becomes
        something people stop reading."""
        assert "base_image_upgrade" not in _ids(_suggest("FROM cgr.dev/chainguard/node:latest\n"))

    def test_distroless_is_left_alone(self):
        suggestions = _suggest("FROM gcr.io/distroless/static-debian12:nonroot\n")
        assert "base_image_upgrade" not in _ids(suggestions)

    def test_scratch_needs_no_base_advice(self):
        assert "base_image_upgrade" not in _ids(_suggest("FROM scratch\n"))

    def test_an_unrecognised_base_gets_no_invented_advice(self):
        assert "base_image_upgrade" not in _ids(_suggest("FROM internal/mystery:1.0\n"))

    def test_only_the_final_stage_is_considered(self):
        """A builder stage's base never ships, so recommending a hardened
        replacement for it is noise."""
        suggestions = _suggest("FROM ubuntu:24.04 AS b\nFROM cgr.dev/chainguard/node:latest\n")
        assert "base_image_upgrade" not in _ids(suggestions)


class TestBuildKitSecrets:
    def test_an_install_consuming_a_token_arg_is_flagged(self):
        """The ARG never reaches a final ENV, but it is recorded in the
        layer's command and replayed by `docker history`."""
        text = "FROM node:22-alpine\nARG NPM_TOKEN\nRUN npm ci --token=${NPM_TOKEN}\n"
        [suggestion] = [s for s in _suggest(text) if s.rule_id == "buildkit_secrets"]
        assert suggestion.priority is Priority.HIGH
        assert "--mount=type=secret" in suggestion.suggested

    def test_an_install_already_using_a_secret_mount_is_not_flagged(self):
        text = "FROM node:22-alpine\nRUN --mount=type=secret,id=npm npm ci --token=${NPM_TOKEN}\n"
        assert "buildkit_secrets" not in _ids(_suggest(text))

    def test_an_ordinary_install_is_not_flagged(self):
        text = "FROM node:22-alpine\nRUN npm ci --omit=dev\n"
        assert "buildkit_secrets" not in _ids(_suggest(text))


class TestSbomLabel:
    def test_missing_sbom_metadata_is_suggested(self):
        assert "sbom_declaration" in _ids(_suggest("FROM alpine:3.19\n"))

    def test_an_existing_sbom_label_suppresses_it(self):
        text = 'FROM alpine:3.19\nLABEL sbom.format="cyclonedx"\n'
        assert "sbom_declaration" not in _ids(_suggest(text))


class TestOrderingAndStability:
    TEXT = "FROM node:22\nARG NPM_TOKEN\nRUN npm ci --token=${NPM_TOKEN}\n"

    def test_high_priority_advice_comes_first(self):
        priorities = [s.priority for s in _suggest(self.TEXT)]
        order = {Priority.HIGH: 0, Priority.MEDIUM: 1, Priority.LOW: 2}
        assert priorities == sorted(priorities, key=lambda p: order[p])

    def test_the_same_dockerfile_always_yields_the_same_list(self):
        assert _ids(_suggest(self.TEXT)) == _ids(_suggest(self.TEXT))
