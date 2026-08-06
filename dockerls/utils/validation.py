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
    return name


def validate_threshold(value: int, name: str) -> int:
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    if value > 10000:
        raise ValueError(f"{name} exceeds maximum allowed value")
    return value
