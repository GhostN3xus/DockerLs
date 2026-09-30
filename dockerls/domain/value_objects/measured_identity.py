"""What was asked for, what it resolved to, and what was actually measured.

Three different strings used to be one. A user types ``node:22``; the
registry says that tag currently points at index ``sha256:aaa`` whose
``linux/amd64`` manifest is ``sha256:bbb``; and the scanner is handed some
reference and measures whatever *that* resolves to at the moment it pulls.
When the last one is the tag again -- as it was -- a tag that moves between
resolution and pull produces a scan of one image filed under the digest of
another.

`ResolvedIdentity` keeps the three apart and refuses to call anything
*confirmed* unless the registry told us the digest of the exact manifest for
the requested platform. Only a confirmed identity may become immutable
evidence (a cache row other commands will trust); anything else is still
measured and reported, with its limitation stated, but never stored as if the
bytes were pinned.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from dockerls.domain.value_objects.image_identity import (
    ImageIdentity,
    split_registry_and_repository,
)

if TYPE_CHECKING:
    from dockerls.domain.value_objects.platform import Platform


_CANONICAL_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


class IdentityStatus(StrEnum):
    #: The registry answered with the digest of the exact platform manifest.
    CONFIRMED = "CONFIRMED"
    #: The user supplied a digest and the registry was not asked, or did not
    #: answer. The bytes are named, but which platform they are for is not
    #: verified.
    DIGEST_ONLY = "DIGEST_ONLY"
    #: Nothing pinned: the registry did not answer or the tag is unknown.
    UNRESOLVED = "UNRESOLVED"
    #: The digest exists but belongs to a different platform than requested,
    #: or the index has no manifest for the requested one.
    PLATFORM_MISMATCH = "PLATFORM_MISMATCH"


@dataclass(frozen=True, slots=True)
class ImageRefs:
    """The three references, never conflated.

    * `requested` -- as the user (or the discovery step) wrote it.
    * `resolved` -- ``name@<platform manifest digest>``, or "" when the
      identity could not be confirmed.
    * `measured` -- the reference the scanner was actually given. Equal to
      `resolved` whenever the identity is confirmed; the tag otherwise.
    """

    requested: str
    resolved: str = ""
    measured: str = ""


@dataclass(frozen=True, slots=True)
class ResolvedIdentity:
    name: str
    tag: str
    platform: Platform
    status: IdentityStatus
    #: Digest of the multi-arch index the tag pointed at, or "" for a tag that
    #: names a single manifest. Never the digest that is scanned.
    index_digest: str = ""
    #: Digest of the manifest for `platform` -- the content that is measured.
    manifest_digest: str = ""
    #: Why the identity is not confirmed, in the reader's terms.
    limitation: str = ""

    @property
    def confirmed(self) -> bool:
        # A digest that is not canonical `sha256:<64 hex>` cannot be an
        # identity, whatever the source claimed: registry and catalogue
        # responses are untrusted input.
        return self.status is IdentityStatus.CONFIRMED and bool(
            _CANONICAL_DIGEST.fullmatch(self.manifest_digest)
        )

    @property
    def resolved_reference(self) -> str:
        """The immutable reference to deploy and to hand a scanner."""
        return f"{self.name}@{self.manifest_digest}" if self.confirmed else ""

    @property
    def identity(self) -> ImageIdentity | None:
        """The strict, content-addressed identity -- only when confirmed."""
        if not self.confirmed:
            return None
        registry, repository = split_registry_and_repository(self.name)
        try:
            return ImageIdentity(
                registry=registry,
                repository=repository,
                digest=self.manifest_digest,
                platform=str(self.platform),
            )
        except ValueError:
            return None

    def refs(self, requested: str, measured: str) -> ImageRefs:
        return ImageRefs(requested=requested, resolved=self.resolved_reference, measured=measured)
