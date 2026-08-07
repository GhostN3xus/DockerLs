"""BuildKit argument construction and the validation that guards it.

Every value here ends up as an argv element passed to `docker` (never
through a shell), but argv is still an interface an attacker can bend: a
build arg named `--build-arg` or a tag beginning with `-` becomes a *flag*
rather than a value. These validators reject that shape at the boundary.
"""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING

from dockerls.utils.validation import sanitize_image_name

if TYPE_CHECKING:
    from dockerls.application.dto.build import BuildOptions, BuildSecret

_ARG_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_LABEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SECRET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

MAX_VALUE_LENGTH = 4096


class BuildArgumentError(ValueError):
    """A build argument, label, secret or tag that must not be forwarded."""


def validate_tag(tag: str) -> str:
    """An image tag is an image reference; reuse the reference validator so
    `build` and `analyze` agree on what a legal reference is."""
    if not tag:
        raise BuildArgumentError("An image tag is required (--tag)")
    if tag.startswith("-"):
        raise BuildArgumentError(f"Image tag must not start with '-': {tag}")
    try:
        return sanitize_image_name(tag)
    except ValueError as e:
        raise BuildArgumentError(str(e)) from e


def validate_build_args(args: dict[str, str]) -> dict[str, str]:
    validated: dict[str, str] = {}
    for name, value in args.items():
        if not _ARG_NAME.match(name):
            raise BuildArgumentError(
                f"Invalid build arg name '{name}': expected a shell-style identifier"
            )
        text = str(value)
        if len(text) > MAX_VALUE_LENGTH:
            raise BuildArgumentError(f"Build arg '{name}' exceeds {MAX_VALUE_LENGTH} characters")
        if "\n" in text or "\0" in text:
            raise BuildArgumentError(f"Build arg '{name}' contains a control character")
        validated[name] = text
    return validated


def validate_labels(labels: dict[str, str]) -> dict[str, str]:
    validated: dict[str, str] = {}
    for name, value in labels.items():
        if not _LABEL_NAME.match(name):
            raise BuildArgumentError(f"Invalid label name '{name}'")
        text = str(value)
        if len(text) > MAX_VALUE_LENGTH:
            raise BuildArgumentError(f"Label '{name}' exceeds {MAX_VALUE_LENGTH} characters")
        if "\n" in text or "\0" in text:
            raise BuildArgumentError(f"Label '{name}' contains a control character")
        validated[name] = text
    return validated


def validate_secret(secret: BuildSecret) -> BuildSecret:
    if not _SECRET_ID.match(secret.secret_id):
        raise BuildArgumentError(f"Invalid secret id '{secret.secret_id}'")
    if secret.env and secret.file:
        raise BuildArgumentError(
            f"Secret '{secret.secret_id}' names both an env var and a file; pick one"
        )
    if not secret.env and not secret.file:
        raise BuildArgumentError(f"Secret '{secret.secret_id}' names neither an env var nor a file")
    if secret.env and not _ENV_NAME.match(secret.env):
        raise BuildArgumentError(f"Invalid environment variable name '{secret.env}'")
    if secret.env and secret.env not in os.environ:
        raise BuildArgumentError(
            f"Secret '{secret.secret_id}' reads ${secret.env}, which is not set"
        )
    return secret


def build_command(options: BuildOptions) -> list[str]:
    """Assemble the full `docker build` argv for `options`.

    `--` terminates the flags before the context path so a context
    directory that starts with a dash cannot be read as one.
    """
    tag = validate_tag(options.tag)
    args = validate_build_args(options.build_args)
    labels = validate_labels(options.labels)

    cmd = ["docker", "build", "--file", options.dockerfile_path, "--tag", tag]

    if options.buildkit and options.inline_cache:
        # Publishes the cache metadata inside the image so a later build on
        # another machine can reuse the layers.
        args.setdefault("BUILDKIT_INLINE_CACHE", "1")

    for name, value in sorted(args.items()):
        cmd += ["--build-arg", f"{name}={value}"]
    for name, value in sorted(labels.items()):
        cmd += ["--label", f"{name}={value}"]
    for secret in options.secrets:
        cmd += ["--secret", validate_secret(secret).to_cli_argument()]

    if options.no_cache:
        cmd.append("--no-cache")
    if options.platform:
        cmd += ["--platform", options.platform]
    if options.target:
        cmd += ["--target", options.target]
    if options.buildkit:
        # Plain progress keeps the log file readable; the TTY renderer emits
        # cursor escapes that make an archived build log unreadable.
        cmd += ["--progress", "plain"]

    cmd += ["--", options.context_path]
    return cmd


def build_environment(options: BuildOptions) -> dict[str, str]:
    """The environment for the build subprocess.

    Inherits the caller's environment because `--secret id=x,env=Y` reads Y
    from it, and because registry credentials live in the Docker config
    that `docker` resolves from HOME.
    """
    env = dict(os.environ)
    env["DOCKER_BUILDKIT"] = "1" if options.buildkit else "0"
    return env
