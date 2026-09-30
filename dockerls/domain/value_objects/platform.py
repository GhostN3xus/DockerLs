"""The platform an image is measured for: ``os/architecture[/variant]``.

A multi-arch tag is not one image. ``node:22`` names an index that points at
one manifest per platform, and each manifest has its own digest, its own
layers and -- for the parts that differ per architecture, such as compiled
packages -- its own findings. A result measured for ``linux/amd64`` says
nothing about ``linux/arm64``, so the platform is part of every identity,
cache key and evidence record rather than an optional filter.

Everything here is pure: parsing, validation, and the matching rule against
an OCI index entry. Nothing touches the network.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_PART = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,31}$")

#: Aliases the OCI/Go ecosystem uses for the same architecture. Normalised on
#: input so ``x86_64`` and ``amd64`` cannot end up as two cache namespaces for
#: the same bytes.
_ARCH_ALIASES = {
    "x86_64": "amd64",
    "x86-64": "amd64",
    "aarch64": "arm64",
    "armhf": "arm",
    "armel": "arm",
}

#: The variant a bare ``arm``/``arm64`` request means when an index publishes
#: several. Mirrors containerd's default platform ordering: v8 for arm64, v7
#: for 32-bit arm.
_DEFAULT_VARIANT = {"arm64": "v8", "arm": "v7"}


class InvalidPlatformError(ValueError):
    """The text is not a well-formed ``os/architecture[/variant]``."""


@dataclass(frozen=True, slots=True)
class Platform:
    os: str
    architecture: str
    variant: str = ""

    def __post_init__(self) -> None:
        for name, value, required in (
            ("os", self.os, True),
            ("architecture", self.architecture, True),
            ("variant", self.variant, False),
        ):
            if not value and not required:
                continue
            if not _PART.fullmatch(value):
                raise InvalidPlatformError(f"invalid platform {name}: {value!r}")

    @classmethod
    def parse(cls, text: str) -> Platform:
        """Parse ``os/arch[/variant]``.

        Strict on purpose: the value is spliced into scanner argv and into
        cache keys, so anything that is not lowercase alphanumerics with
        ``._-`` is refused instead of being cleaned up into something the
        caller did not type.
        """
        value = text.strip().lower()
        parts = value.split("/")
        if len(parts) not in (2, 3) or not all(parts):
            raise InvalidPlatformError(f"platform must be os/architecture[/variant], got {text!r}")
        os_name, architecture = parts[0], _ARCH_ALIASES.get(parts[1], parts[1])
        variant = parts[2] if len(parts) == 3 else ""
        return cls(os=os_name, architecture=architecture, variant=variant)

    @classmethod
    def from_index_entry(cls, entry: dict[str, Any]) -> Platform | None:
        """The platform an OCI index entry declares, or None when unusable.

        Attestation manifests (cosign, SLSA) sit in the same index and declare
        ``unknown/unknown``; they are not images and never a candidate.
        """
        raw = entry.get("platform")
        if not isinstance(raw, dict):
            return None
        os_name = str(raw.get("os") or "").lower()
        architecture = _ARCH_ALIASES.get(
            str(raw.get("architecture") or "").lower(), str(raw.get("architecture") or "").lower()
        )
        if not os_name or not architecture or "unknown" in (os_name, architecture):
            return None
        try:
            return cls(os_name, architecture, str(raw.get("variant") or "").lower())
        except InvalidPlatformError:
            return None

    def satisfied_by(self, candidate: Platform) -> bool:
        """Whether `candidate` is an acceptable answer to this request.

        A request without a variant accepts any variant of that architecture
        (the caller then disambiguates); a request with one requires it
        exactly. Never the other way round: asking for ``linux/arm/v7`` must
        not be served by a ``v6`` manifest.
        """
        if (self.os, self.architecture) != (candidate.os, candidate.architecture):
            return False
        return not self.variant or self.variant == candidate.variant

    @property
    def default_variant(self) -> str:
        return _DEFAULT_VARIANT.get(self.architecture, "")

    def __str__(self) -> str:
        return "/".join(p for p in (self.os, self.architecture, self.variant) if p)


#: What is measured when nothing is asked for. The registry inspector always
#: preferred ``linux/amd64`` and the Hub client reports it first; scanners, on
#: the other hand, silently used the *host's* architecture. Making the default
#: explicit -- and passing it to every scanner -- is what stops an arm64 CI
#: runner from attributing arm64 findings to an image the report calls amd64.
DEFAULT_PLATFORM = Platform("linux", "amd64")


def parse_platform(text: str | None) -> Platform:
    """`text` as a Platform, or the default when nothing was requested."""
    if text is None or not text.strip():
        return DEFAULT_PLATFORM
    return Platform.parse(text)
