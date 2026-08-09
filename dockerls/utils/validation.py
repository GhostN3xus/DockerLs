from __future__ import annotations

import re

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


def validate_threshold(value: int, name: str) -> int:
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    if value > 10000:
        raise ValueError(f"{name} exceeds maximum allowed value")
    return value
