"""One test per rule, in both directions.

A security rule that only ever fires is as useless as one that never
fires -- the first trains users to ignore it, the second lets the bug
through -- so every rule below is exercised on a Dockerfile it must flag
*and* one it must leave alone.
"""

import pytest

from dockerls.application.services.dockerfile_validator import OwaspDockerfileValidator
from dockerls.domain.entities.build_validation import CheckStatus, HardeningLevel
from dockerls.domain.entities.vulnerability import Severity
from dockerls.infrastructure.validators.dockerfile_security_rules import RULE_COUNT

CLEAN = """\
ARG ALPINE_VERSION=3.19
FROM alpine:${ALPINE_VERSION} AS builder
RUN apk add --no-cache gcc
COPY . .
RUN echo build

FROM alpine:${ALPINE_VERSION}
LABEL maintainer="team@example.com"
LABEL security.cve-contact="security@example.com"
RUN addgroup -g 1000 appgroup && adduser -D -u 1000 -G appgroup appuser
COPY --from=builder --chown=appuser:appgroup /app /app
USER appuser
HEALTHCHECK --interval=30s CMD ["/app/health"]
ENTRYPOINT ["/app/server"]
"""


def _validate(tmp_path, text, context=None, **kwargs):
    path = tmp_path / "Dockerfile"
    path.write_text(text)
    validator = OwaspDockerfileValidator(**kwargs)
    return validator.validate(path, context)


def _check(result, rule_id):
    for check in result.checks:
        if check.check == rule_id:
            return check
    raise AssertionError(f"rule {rule_id} did not run")


class TestCleanDockerfile:
    def test_every_rule_is_reported(self, tmp_path):
        result = _validate(tmp_path, CLEAN)
        assert len(result.checks) == RULE_COUNT

    def test_a_hardened_dockerfile_has_no_findings(self, tmp_path):
        result = _validate(tmp_path, CLEAN)
        offenders = [c.check for c in result.checks if c.failed]
        assert offenders == []
        assert result.score == 100.0

    def test_no_blocking_findings(self, tmp_path):
        assert not _validate(tmp_path, CLEAN).has_blocking_findings


class TestSecretsInEnv:
    @pytest.mark.parametrize(
        "line",
        [
            "ENV NPM_TOKEN=abc123",
            "ENV DOCKERHUB_PASSWORD=hunter2",
            'ENV AWS_SECRET_ACCESS_KEY="wJalrXUt"',
            "ARG GITHUB_TOKEN=ghp_realtoken",
            "ENV API_KEY value-here",
        ],
    )
    def test_detects_credentials(self, tmp_path, line):
        result = _validate(tmp_path, f"FROM alpine:3.19\n{line}\nUSER app\n")
        check = _check(result, "secrets_not_in_env")
        assert check.status is CheckStatus.FAIL
        assert check.severity is Severity.CRITICAL
        assert check.line == 2

    @pytest.mark.parametrize(
        "line",
        [
            # A path names where a secret will be mounted; it is not one.
            "ENV API_KEY_FILE=/run/secrets/api_key",
            # An indirection defers to a build arg rather than baking a value.
            "ENV NPM_TOKEN=$BUILD_TOKEN",
            "ENV NPM_TOKEN=",
            "ENV NODE_ENV=production",
            "ENV PATH=/home/appuser/.local/bin:$PATH",
        ],
    )
    def test_does_not_flag_non_credentials(self, tmp_path, line):
        result = _validate(tmp_path, f"FROM alpine:3.19\n{line}\nUSER app\n")
        assert _check(result, "secrets_not_in_env").status is CheckStatus.PASS


class TestSecretFiles:
    @pytest.mark.parametrize(
        "line",
        ["COPY .env /app/", "COPY id_rsa /root/.ssh/id_rsa", "ADD server.pem /certs/server.pem"],
    )
    def test_flags_credential_files(self, tmp_path, line):
        result = _validate(tmp_path, f"FROM alpine:3.19\n{line}\n")
        assert _check(result, "no_secret_files_copied").status is CheckStatus.FAIL

    def test_stage_to_stage_copy_is_not_a_host_leak(self, tmp_path):
        text = "FROM alpine:3.19 AS b\nFROM alpine:3.19\nCOPY --from=b /app/.env /app/.env\n"
        result = _validate(tmp_path, text)
        assert _check(result, "no_secret_files_copied").status is CheckStatus.PASS


class TestNonRootUser:
    def test_missing_user_directive_fails(self, tmp_path):
        result = _validate(tmp_path, 'FROM alpine:3.19\nENTRYPOINT ["/app"]\n')
        assert _check(result, "non_root_user").status is CheckStatus.FAIL

    def test_explicit_root_fails(self, tmp_path):
        result = _validate(tmp_path, "FROM alpine:3.19\nUSER root\n")
        assert _check(result, "non_root_user").status is CheckStatus.FAIL

    def test_numeric_uid_passes(self, tmp_path):
        result = _validate(tmp_path, "FROM scratch\nUSER 65532:65532\n")
        assert _check(result, "non_root_user").status is CheckStatus.PASS

    def test_distroless_nonroot_variant_passes(self, tmp_path):
        result = _validate(tmp_path, "FROM gcr.io/distroless/static-debian12:nonroot\n")
        assert _check(result, "non_root_user").status is CheckStatus.PASS

    def test_only_the_final_stage_user_counts(self, tmp_path):
        """Building as root is normal; *shipping* as root is the finding."""
        text = "FROM alpine:3.19 AS b\nUSER root\nFROM alpine:3.19\nUSER appuser\n"
        assert _check(_validate(tmp_path, text), "non_root_user").status is CheckStatus.PASS


class TestBaseImagePinned:
    @pytest.mark.parametrize("reference", ["node:latest", "node", "ubuntu:LATEST"])
    def test_unpinned_bases_fail(self, tmp_path, reference):
        result = _validate(tmp_path, f"FROM {reference}\nUSER app\n")
        assert _check(result, "base_image_pinned").status is CheckStatus.FAIL

    def test_pinned_tag_passes(self, tmp_path):
        result = _validate(tmp_path, "FROM node:22.11.0-alpine3.19\nUSER app\n")
        assert _check(result, "base_image_pinned").status is CheckStatus.PASS

    def test_digest_passes(self, tmp_path):
        result = _validate(tmp_path, f"FROM node@sha256:{'b' * 64}\nUSER app\n")
        assert _check(result, "base_image_pinned").status is CheckStatus.PASS

    def test_scratch_passes(self, tmp_path):
        result = _validate(tmp_path, "FROM scratch\nUSER 1000\n")
        assert _check(result, "base_image_pinned").status is CheckStatus.PASS

    def test_stage_reference_is_not_an_unpinned_image(self, tmp_path):
        text = "FROM alpine:3.19 AS builder\nFROM builder\nUSER app\n"
        assert _check(_validate(tmp_path, text), "base_image_pinned").status is CheckStatus.PASS

    def test_arg_pinned_version_passes(self, tmp_path):
        text = "ARG V=22.11.0\nFROM node:${V}-alpine\nUSER app\n"
        assert _check(_validate(tmp_path, text), "base_image_pinned").status is CheckStatus.PASS


class TestSudoAndSetuid:
    @pytest.mark.parametrize(
        "line",
        ["RUN apk add --no-cache sudo", "RUN sudo apk update", "RUN echo x && sudo sh"],
    )
    def test_sudo_is_flagged(self, tmp_path, line):
        result = _validate(tmp_path, f"FROM alpine:3.19\n{line}\nUSER app\n")
        assert _check(result, "no_sudo").status is CheckStatus.FAIL

    def test_pseudo_word_is_not_sudo(self, tmp_path):
        result = _validate(tmp_path, "FROM alpine:3.19\nRUN echo pseudocode\nUSER app\n")
        assert _check(result, "no_sudo").status is CheckStatus.PASS

    @pytest.mark.parametrize("line", ["RUN chmod 4755 /app", "RUN chmod u+s /bin/x"])
    def test_setuid_is_flagged(self, tmp_path, line):
        result = _validate(tmp_path, f"FROM alpine:3.19\n{line}\nUSER app\n")
        assert _check(result, "no_setuid_binaries").status is CheckStatus.FAIL

    def test_ordinary_chmod_passes(self, tmp_path):
        result = _validate(tmp_path, "FROM alpine:3.19\nRUN chmod 0755 /app\nUSER app\n")
        assert _check(result, "no_setuid_binaries").status is CheckStatus.PASS


class TestPackageHygiene:
    def test_apt_install_without_flag_warns(self, tmp_path):
        text = "FROM debian:12\nRUN apt-get update && apt-get install -y curl\nUSER app\n"
        assert _check(_validate(tmp_path, text), "apt_no_install_recommends").failed

    def test_apt_install_with_flag_passes(self, tmp_path):
        text = (
            "FROM debian:12\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends curl "
            "&& rm -rf /var/lib/apt/lists/*\nUSER app\n"
        )
        result = _validate(tmp_path, text)
        assert _check(result, "apt_no_install_recommends").status is CheckStatus.PASS
        assert _check(result, "package_cache_clean").status is CheckStatus.PASS

    def test_no_apt_means_the_rule_is_skipped_not_passed(self, tmp_path):
        """A rule that never ran must not inflate the pass count."""
        result = _validate(tmp_path, "FROM alpine:3.19\nUSER app\n")
        assert _check(result, "apt_no_install_recommends").status is CheckStatus.SKIP

    def test_dirty_apk_install_warns(self, tmp_path):
        text = "FROM alpine:3.19\nRUN apk add curl\nUSER app\n"
        assert _check(_validate(tmp_path, text), "package_cache_clean").failed

    def test_apk_no_cache_passes(self, tmp_path):
        text = "FROM alpine:3.19\nRUN apk add --no-cache curl\nUSER app\n"
        assert _check(_validate(tmp_path, text), "package_cache_clean").status is CheckStatus.PASS

    def test_builder_stage_installs_do_not_count(self, tmp_path):
        text = "FROM alpine:3.19 AS b\nRUN apk add curl\nFROM alpine:3.19\nUSER app\n"
        assert _check(_validate(tmp_path, text), "package_cache_clean").status is CheckStatus.SKIP


class TestStructureRules:
    def test_single_stage_warns(self, tmp_path):
        assert _check(_validate(tmp_path, "FROM alpine:3.19\nUSER app\n"), "multi_stage").failed

    def test_single_stage_from_scratch_passes(self, tmp_path):
        result = _validate(tmp_path, "FROM scratch\nUSER 1000\n")
        assert _check(result, "multi_stage").status is CheckStatus.PASS

    @pytest.mark.parametrize(
        "reference", ["alpine:3.19", "python:3.12-slim", "gcr.io/distroless/base", "scratch"]
    )
    def test_minimal_bases_pass(self, tmp_path, reference):
        result = _validate(tmp_path, f"FROM {reference}\nUSER app\n")
        assert _check(result, "minimal_base").status is CheckStatus.PASS

    @pytest.mark.parametrize("reference", ["ubuntu:24.04", "debian:12", "node:22"])
    def test_full_distributions_warn(self, tmp_path, reference):
        assert _check(_validate(tmp_path, f"FROM {reference}\nUSER app\n"), "minimal_base").failed

    def test_shell_form_entrypoint_warns(self, tmp_path):
        text = "FROM alpine:3.19\nUSER app\nENTRYPOINT /app/server\n"
        assert _check(_validate(tmp_path, text), "exec_form_entrypoint").failed

    def test_exec_form_passes(self, tmp_path):
        text = 'FROM alpine:3.19\nUSER app\nENTRYPOINT ["/app/server"]\n'
        result = _validate(tmp_path, text)
        assert _check(result, "exec_form_entrypoint").status is CheckStatus.PASS

    def test_no_entrypoint_at_all_warns(self, tmp_path):
        assert _check(
            _validate(tmp_path, "FROM alpine:3.19\nUSER app\n"), "exec_form_entrypoint"
        ).failed

    def test_healthcheck_none_does_not_count(self, tmp_path):
        text = "FROM alpine:3.19\nUSER app\nHEALTHCHECK NONE\n"
        assert _check(_validate(tmp_path, text), "healthcheck").failed

    def test_remote_add_warns(self, tmp_path):
        text = "FROM alpine:3.19\nADD https://example.com/x.tgz /tmp/\nUSER app\n"
        assert _check(_validate(tmp_path, text), "no_remote_add").failed

    def test_local_add_passes(self, tmp_path):
        text = "FROM alpine:3.19\nADD app.tgz /app/\nUSER app\n"
        assert _check(_validate(tmp_path, text), "no_remote_add").status is CheckStatus.PASS


class TestLabels:
    def test_owner_without_security_metadata_warns(self, tmp_path):
        text = 'FROM alpine:3.19\nLABEL maintainer="a@b.c"\nUSER app\n'
        assert _check(_validate(tmp_path, text), "security_labels").failed

    def test_both_present_passes(self, tmp_path):
        text = 'FROM alpine:3.19\nLABEL maintainer="a@b.c" security.scanner="dockerls"\nUSER app\n'
        assert _check(_validate(tmp_path, text), "security_labels").status is CheckStatus.PASS

    def test_legacy_maintainer_instruction_counts_as_an_owner(self, tmp_path):
        text = 'FROM alpine:3.19\nMAINTAINER a@b.c\nLABEL security.policy="x"\nUSER app\n'
        assert _check(_validate(tmp_path, text), "security_labels").status is CheckStatus.PASS


class TestDockerignore:
    def test_missing_dockerignore_with_wide_copy_warns(self, tmp_path):
        result = _validate(tmp_path, "FROM alpine:3.19\nCOPY . .\nUSER app\n", context=tmp_path)
        assert _check(result, "dockerignore_present").failed

    def test_dockerignore_covering_git_and_env_passes(self, tmp_path):
        (tmp_path / ".dockerignore").write_text(".git\n.env\nnode_modules\n")
        result = _validate(tmp_path, "FROM alpine:3.19\nCOPY . .\nUSER app\n", context=tmp_path)
        assert _check(result, "dockerignore_present").status is CheckStatus.PASS

    def test_incomplete_dockerignore_names_what_is_missing(self, tmp_path):
        (tmp_path / ".dockerignore").write_text("node_modules\n")
        result = _validate(tmp_path, "FROM alpine:3.19\nCOPY . .\nUSER app\n", context=tmp_path)
        check = _check(result, "dockerignore_present")
        assert ".git" in check.message and ".env" in check.message

    def test_no_wide_copy_needs_no_dockerignore(self, tmp_path):
        result = _validate(
            tmp_path, "FROM alpine:3.19\nCOPY app.js /app/\nUSER app\n", context=tmp_path
        )
        assert _check(result, "dockerignore_present").status is CheckStatus.PASS

    def test_without_a_context_the_rule_is_skipped(self, tmp_path):
        result = _validate(tmp_path, "FROM alpine:3.19\nCOPY . .\nUSER app\n")
        assert _check(result, "dockerignore_present").status is CheckStatus.SKIP


class TestHardeningLevels:
    # One HIGH finding (unpinned base) and several MEDIUM ones, so each
    # level draws a visibly different line.
    BAD = "FROM node:latest\nRUN apk add curl\nUSER appuser\n"

    def test_relaxed_only_blocks_on_critical(self, tmp_path):
        result = _validate(tmp_path, self.BAD, hardening_level=HardeningLevel.RELAXED)
        assert not result.has_blocking_findings

    def test_standard_blocks_on_high(self, tmp_path):
        result = _validate(tmp_path, self.BAD, hardening_level=HardeningLevel.STANDARD)
        assert [c.check for c in result.blocking] == ["base_image_pinned"]

    def test_strict_also_blocks_on_medium(self, tmp_path):
        result = _validate(tmp_path, self.BAD, hardening_level=HardeningLevel.STRICT)
        assert len(result.blocking) > 1

    def test_findings_are_identical_at_every_level(self, tmp_path):
        """Only the *decision* changes with the level. If the findings
        themselves moved, a relaxed run would hide problems rather than
        merely tolerate them."""
        levels = [_validate(tmp_path, self.BAD, hardening_level=level) for level in HardeningLevel]
        failed = [{c.check for c in r.checks if c.failed} for r in levels]
        assert failed[0] == failed[1] == failed[2]


class TestSkipRules:
    def test_waived_rule_is_reported_as_skipped_not_dropped(self, tmp_path):
        result = _validate(
            tmp_path, "FROM node:latest\nUSER app\n", skip_rules=["base_image_pinned"]
        )
        check = _check(result, "base_image_pinned")
        assert check.status is CheckStatus.SKIP
        assert "policy" in check.message
        assert not result.has_blocking_findings


class TestUnparseableDockerfile:
    def test_missing_file_becomes_a_critical_finding(self, tmp_path):
        validator = OwaspDockerfileValidator()
        result = validator.validate(tmp_path / "nope")
        assert result.failures[0].check == "dockerfile_parseable"
        assert result.has_blocking_findings
        assert result.score < 100
