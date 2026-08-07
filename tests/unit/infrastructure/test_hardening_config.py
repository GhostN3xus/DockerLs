"""`.dockerls-hardening.yaml` is a security gate written down.

Its central property is that a malformed policy is *fatal*: quietly falling
back to defaults would turn a gated pipeline into an ungated one, which is
exactly the failure a policy file exists to prevent.
"""

import pytest

from dockerls.domain.entities.build_validation import HardeningLevel
from dockerls.infrastructure.config.hardening import (
    DEFAULT_HARDENING_FILENAME,
    HardeningConfigError,
    find_hardening_config,
    load_hardening_config,
)

FULL_POLICY = """\
build:
  validation:
    hardening_level: strict
    skip_rules: [healthcheck]
  scanning:
    enabled: true
    fail_on: high
    sbom_formats: [cyclonedx, spdx]
  reporting:
    formats: [json, html, sarif]
    vault_push: true
    vault_path: infraestrutura/builds
  buildkit:
    enabled: true
    inline_cache: false

projects:
  - name: api
    dockerfile: ./api/Dockerfile
    context: ./api
    tag: "api:latest"
    hardened_template: node
  - name: web
    tag: "web:latest"
    push: true
"""


def _write(tmp_path, text, name=DEFAULT_HARDENING_FILENAME):
    path = tmp_path / name
    path.write_text(text)
    return path


class TestLoading:
    def test_no_file_yields_usable_defaults(self):
        config = load_hardening_config(None)
        assert config.validation.hardening_level is HardeningLevel.STANDARD
        assert config.scanning.fail_on == "critical"
        assert config.reporting.formats == ["json"]

    def test_a_full_policy_round_trips(self, tmp_path):
        config = load_hardening_config(_write(tmp_path, FULL_POLICY))
        assert config.validation.hardening_level is HardeningLevel.STRICT
        assert config.validation.skip_rules == ["healthcheck"]
        assert config.scanning.fail_on == "high"
        assert config.scanning.sbom_formats == ["cyclonedx", "spdx"]
        assert config.reporting.formats == ["json", "html", "sarif"]
        assert config.buildkit.inline_cache is False
        assert [p.name for p in config.projects] == ["api", "web"]
        assert config.projects[1].push is True

    def test_a_flat_policy_without_the_build_key_also_works(self, tmp_path):
        config = load_hardening_config(_write(tmp_path, "scanning:\n  fail_on: medium\n"))
        assert config.scanning.fail_on == "medium"

    def test_the_source_path_is_recorded(self, tmp_path):
        path = _write(tmp_path, FULL_POLICY)
        assert load_hardening_config(path).source_path == str(path)


class TestInvalidPolicyIsFatal:
    def test_malformed_yaml_raises(self, tmp_path):
        with pytest.raises(HardeningConfigError, match="Could not read"):
            load_hardening_config(_write(tmp_path, "scanning:\n  - [unclosed\n"))

    def test_a_non_mapping_document_raises(self, tmp_path):
        with pytest.raises(HardeningConfigError, match="mapping"):
            load_hardening_config(_write(tmp_path, "- just\n- a list\n"))

    def test_an_unknown_fail_on_threshold_raises(self, tmp_path):
        with pytest.raises(HardeningConfigError, match="fail_on"):
            load_hardening_config(_write(tmp_path, "scanning:\n  fail_on: whenever\n"))

    def test_an_unknown_report_format_raises(self, tmp_path):
        with pytest.raises(HardeningConfigError, match="format"):
            load_hardening_config(_write(tmp_path, "reporting:\n  formats: [pdf]\n"))

    def test_an_unknown_hardening_level_raises(self, tmp_path):
        with pytest.raises(HardeningConfigError):
            load_hardening_config(_write(tmp_path, "validation:\n  hardening_level: paranoid\n"))

    def test_a_project_without_a_tag_raises(self, tmp_path):
        with pytest.raises(HardeningConfigError):
            load_hardening_config(_write(tmp_path, "projects:\n  - name: api\n"))


class TestDiscovery:
    def test_finds_the_policy_beside_the_context(self, tmp_path):
        path = _write(tmp_path, "scanning:\n  fail_on: high\n")
        assert find_hardening_config(tmp_path) == path

    def test_walks_up_for_a_monorepo_service_directory(self, tmp_path):
        path = _write(tmp_path, "scanning:\n  fail_on: high\n")
        service = tmp_path / "services" / "api"
        service.mkdir(parents=True)
        assert find_hardening_config(service) == path

    def test_a_dockerfile_path_resolves_from_its_directory(self, tmp_path):
        path = _write(tmp_path, "scanning:\n  fail_on: high\n")
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM alpine:3.19\n")
        assert find_hardening_config(dockerfile) == path

    def test_returns_none_when_there_is_no_policy(self, tmp_path):
        # tmp_path is well below any repository that might carry one.
        assert find_hardening_config(tmp_path) is None
