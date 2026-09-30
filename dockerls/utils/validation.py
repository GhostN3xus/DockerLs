from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

# Supports plain names ("node"), tags ("node:22-alpine"), digest
# references ("node@sha256:<64 hex>"), tag+digest combined, and private
# registry prefixes with an optional port ("ghcr.io/org/repo:tag",
# "registry.internal:5000/team/app@sha256:...").
_IMAGE_NAME_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9.-]+(?::\d+)?/)?"
    r"[a-zA-Z0-9._/-]+"
    r"(?::[a-zA-Z0-9._-]+)?"
    r"(?:@sha256:[a-fA-F0-9]{64})?$"
)
_MAX_NAME_LENGTH = 256


def sanitize_image_name(name: str) -> str:
    name = name.strip()
    if not name:
        raise ValueError("Image name cannot be empty")
    if len(name) > _MAX_NAME_LENGTH:
        raise ValueError(f"Image name exceeds {_MAX_NAME_LENGTH} characters")
    if not _IMAGE_NAME_PATTERN.match(name):
        raise ValueError(f"Invalid image name: {name}")
    if ".." in name:
        raise ValueError("Path traversal detected in image name")
    _reject_option_lookalike(name)
    return name


def _reject_option_lookalike(name: str) -> None:
    """Refuse references that a scanner would read as command-line options.

    The reference is appended to `trivy image …` / `grype …` as the scan
    target. Hyphen is a legal character mid-name, so strings like
    `--ignore-unfixed` or `--offline-scan` satisfied the pattern above and
    were handed to the scanner as *flags* rather than as an image -- turning
    a reference that arrives from a CI variable or a config file into control
    over how (or whether) the scan runs. Docker itself requires every path
    component to start with an alphanumeric, so nothing legitimate is lost.
    """
    for component in name.split("/"):
        if component.startswith("-"):
            raise ValueError(
                f"Invalid image name: {name} (a reference component may not start with '-')"
            )


def sanitize_platform(platform: str | None) -> list[str]:
    """`["--platform", "os/arch[/variant]"]` for a scanner, or `[]`.

    The value is parsed with the same strict rule the CLI uses and re-rendered,
    so nothing the caller typed reaches argv except lowercase alphanumerics and
    `._-/`. Raises `ValueError` for anything else: a malformed platform is a
    refused scan, not a scan of the host's platform.
    """
    if platform is None or not platform.strip():
        return []
    from dockerls.domain.value_objects.platform import Platform

    return ["--platform", str(Platform.parse(platform))]


_MAX_THRESHOLD = 10000

# Each worker holds a slot on an asyncio.Semaphore; 0 would deadlock the
# scan loop forever and anything much above this only adds contention and
# rate-limit pressure on Docker Hub.
MIN_WORKERS = 1
MAX_WORKERS = 50


def validate_threshold(value: int, name: str, *, minimum: int = 0) -> int:
    if value < minimum:
        if minimum == 0:
            raise ValueError(f"{name} must be non-negative")
        raise ValueError(f"{name} must be at least {minimum}")
    if value > _MAX_THRESHOLD:
        raise ValueError(f"{name} exceeds maximum allowed value ({_MAX_THRESHOLD})")
    return value


def validate_workers(value: int, name: str = "workers") -> int:
    if value < MIN_WORKERS or value > MAX_WORKERS:
        raise ValueError(f"{name} must be between {MIN_WORKERS} and {MAX_WORKERS}")
    return value


def validate_output_path(value: str) -> Path:
    """A destination the user typed, checked before anything is written to it.

    Refuses what is almost certainly a mistake or an attempt to make the tool
    overwrite something else: an empty value, a NUL byte, an existing directory,
    a symbolic link (the write would land wherever it points), and anything that
    exists but is not a regular file. The parent directory is created by the
    caller; this only judges the name.
    """
    from pathlib import Path

    if not value or not value.strip():
        raise ValueError("the output path is empty")
    if "\x00" in value:
        raise ValueError("the output path contains a NUL byte")
    path = Path(value).expanduser()
    if path.is_symlink():
        raise ValueError(f"{path} is a symbolic link; refusing to write through it")
    if path.exists() and not path.is_file():
        raise ValueError(f"{path} exists and is not a regular file")
    return path
