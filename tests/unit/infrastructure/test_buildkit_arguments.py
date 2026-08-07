"""Argument construction is a trust boundary.

Nothing here goes through a shell, so quoting is not the risk -- argv
position is. A tag or build arg that starts with `-` becomes a *flag* to
`docker build`, and a secret whose value we accept instead of whose source
we accept defeats the entire point of `--mount=type=secret`.
"""

import pytest

from dockerls.application.dto.build import BuildOptions, BuildSecret
from dockerls.infrastructure.docker.buildkit import (
    BuildArgumentError,
    build_command,
    build_environment,
    validate_build_args,
    validate_labels,
    validate_secret,
    validate_tag,
)


def _options(**kwargs):
    kwargs.setdefault("dockerfile_path", "/src/Dockerfile")
    kwargs.setdefault("context_path", "/src")
    kwargs.setdefault("tag", "app:1.0")
    return BuildOptions(**kwargs)


class TestTagValidation:
    @pytest.mark.parametrize(
        "tag", ["app:1.0", "ghcr.io/org/app:sha-abc123", "registry.internal:5000/team/app:v1"]
    )
    def test_accepts_real_references(self, tag):
        assert validate_tag(tag) == tag

    def test_rejects_a_tag_that_would_be_read_as_a_flag(self):
        with pytest.raises(BuildArgumentError, match="must not start with"):
            validate_tag("--rm")

    def test_rejects_an_empty_tag_with_a_usable_message(self):
        with pytest.raises(BuildArgumentError, match="--tag"):
            validate_tag("")

    def test_rejects_path_traversal(self):
        with pytest.raises(BuildArgumentError):
            validate_tag("../../evil:1.0")


class TestBuildArgValidation:
    def test_accepts_shell_style_identifiers(self):
        assert validate_build_args({"NODE_ENV": "production"}) == {"NODE_ENV": "production"}

    @pytest.mark.parametrize("name", ["--build-arg", "NODE ENV", "no-dashes-allowed", "1START"])
    def test_rejects_names_that_are_not_identifiers(self, name):
        with pytest.raises(BuildArgumentError, match="Invalid build arg name"):
            validate_build_args({name: "x"})

    def test_rejects_a_newline_in_a_value(self):
        with pytest.raises(BuildArgumentError, match="control character"):
            validate_build_args({"X": "a\nb"})

    def test_rejects_an_oversized_value(self):
        with pytest.raises(BuildArgumentError, match="exceeds"):
            validate_build_args({"X": "a" * 5000})

    def test_label_names_allow_dotted_keys(self):
        labels = {"org.opencontainers.image.revision": "abc"}
        assert validate_labels(labels) == labels

    def test_rejects_an_invalid_label_name(self):
        with pytest.raises(BuildArgumentError, match="Invalid label name"):
            validate_labels({"--label": "x"})


class TestSecretValidation:
    def test_env_secret_requires_the_variable_to_exist(self, monkeypatch):
        monkeypatch.delenv("NPM_TOKEN", raising=False)
        with pytest.raises(BuildArgumentError, match="not set"):
            validate_secret(BuildSecret(secret_id="npm", env="NPM_TOKEN"))

    def test_env_secret_passes_when_set(self, monkeypatch):
        monkeypatch.setenv("NPM_TOKEN", "value")
        secret = validate_secret(BuildSecret(secret_id="npm", env="NPM_TOKEN"))
        assert secret.to_cli_argument() == "id=npm,env=NPM_TOKEN"

    def test_file_secret_renders_as_a_source(self):
        secret = BuildSecret(secret_id="npm", file="/run/token")
        assert validate_secret(secret).to_cli_argument() == "id=npm,src=/run/token"

    def test_naming_both_sources_is_refused(self, monkeypatch):
        monkeypatch.setenv("T", "v")
        with pytest.raises(BuildArgumentError, match="pick one"):
            validate_secret(BuildSecret(secret_id="npm", env="T", file="/x"))

    def test_naming_neither_source_is_refused(self):
        with pytest.raises(BuildArgumentError, match="neither"):
            validate_secret(BuildSecret(secret_id="npm"))

    def test_a_secret_never_carries_its_value(self):
        """The model has no field a caller could put the material in, which
        is what keeps it out of argv and out of the log."""
        assert "value" not in BuildSecret.model_fields


class TestCommandConstruction:
    def test_builds_the_expected_argv(self):
        cmd = build_command(_options(build_args={"NODE_ENV": "production"}))
        assert cmd[:2] == ["docker", "build"]
        assert "--file" in cmd
        assert "--tag" in cmd
        assert "NODE_ENV=production" in cmd

    def test_context_is_separated_by_a_double_dash(self):
        """So a context directory starting with a dash cannot be read as a
        flag."""
        cmd = build_command(_options(context_path="-weird-dir"))
        assert cmd[-2:] == ["--", "-weird-dir"]

    def test_inline_cache_is_requested_under_buildkit(self):
        cmd = build_command(_options())
        assert "BUILDKIT_INLINE_CACHE=1" in cmd

    def test_inline_cache_is_omitted_when_disabled(self):
        cmd = build_command(_options(inline_cache=False))
        assert "BUILDKIT_INLINE_CACHE=1" not in cmd

    def test_optional_flags_appear_only_when_requested(self):
        plain = build_command(_options())
        assert "--no-cache" not in plain
        assert "--platform" not in plain

        full = build_command(_options(no_cache=True, platform="linux/arm64", target="runtime"))
        assert "--no-cache" in full
        assert full[full.index("--platform") + 1] == "linux/arm64"
        assert full[full.index("--target") + 1] == "runtime"

    def test_argument_order_is_deterministic(self):
        """Two runs of the same build must produce byte-identical argv, or
        the layer cache misses and build reports cannot be diffed."""
        options = _options(build_args={"B": "2", "A": "1"}, labels={"z": "1", "a": "2"})
        assert build_command(options) == build_command(options)

    def test_a_bad_argument_stops_the_command_from_being_built(self):
        with pytest.raises(BuildArgumentError):
            build_command(_options(build_args={"--evil": "x"}))


class TestEnvironment:
    def test_buildkit_is_enabled_by_default(self):
        assert build_environment(_options())["DOCKER_BUILDKIT"] == "1"

    def test_buildkit_can_be_turned_off(self):
        assert build_environment(_options(buildkit=False))["DOCKER_BUILDKIT"] == "0"

    def test_the_caller_environment_is_inherited(self, monkeypatch):
        """`--secret id=x,env=Y` reads Y from here, and registry credentials
        live in the Docker config resolved from HOME."""
        monkeypatch.setenv("SOME_TOKEN", "value")
        assert build_environment(_options())["SOME_TOKEN"] == "value"
