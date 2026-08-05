from __future__ import annotations

import re

_IMAGE_NAME_PATTERN = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9._/-]*(?::[a-zA-Z0-9._-]+)?$"
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
