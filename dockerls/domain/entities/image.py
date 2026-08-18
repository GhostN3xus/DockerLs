from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from dockerls.domain.entities.declared_metadata import DeclaredImageMetadata

#: Label carried by candidates discovered on Docker Hub. Defined here rather
#: than written as a literal in each provider so the source registry, the
#: results table and the repositories cannot disagree about the spelling.
DOCKER_HUB = "Docker Hub"


class DockerImage(BaseModel):
    name: str
    tag: str
    digest: str = ""
    size_bytes: int = 0
    architecture: str = "amd64"
    available_architectures: list[str] = Field(default_factory=list)
    os: str = "linux"
    last_updated: datetime | None = None
    pull_count: int = 0
    is_official: bool = False
    is_signed: bool = False
    full_reference: str = ""
    # Which catalogue this tag came from: "Docker Hub", "Chainguard",
    # "Distroless". Shown in the results table so a recommendation from a
    # hardened source is identifiable at a glance.
    source: str = DOCKER_HUB
    # What the catalogue that published this image claims about it. Present
    # only for sources that publish build definitions (Docker Hardened
    # Images). A claim, never a measurement -- see DeclaredImageMetadata.
    declared: DeclaredImageMetadata | None = None

    def model_post_init(self, __context: object) -> None:
        if not self.full_reference:
            self.full_reference = f"{self.name}:{self.tag}"

    @property
    def registry_host(self) -> str:
        """Registry this image lives on, or "" for Docker Hub.

        A name is host-qualified only when its first component contains a
        dot or a colon -- `cgr.dev/chainguard/node` is, `library/node` is
        not. That is the same rule the Docker CLI applies.
        """
        head = self.name.split("/", 1)[0]
        return head if ("." in head or ":" in head) else ""

    @property
    def pinned_reference(self) -> str:
        """The immutable reference for this image, when one is known.

        A tag is a moving pointer: `node:22` today and `node:22` next week
        are different bytes, so a recommendation naming only a tag cannot be
        checked against the scan that produced it. When the digest is known
        the pinned form is what should be deployed and what evidence is
        recorded against; without one, the tag is the best available and is
        returned unchanged rather than faked.
        """
        if not self.digest:
            return self.full_reference
        return f"{self.name}@{self.digest}"

    @property
    def digest_known(self) -> bool:
        return bool(self.digest)

    @property
    def age_known(self) -> bool:
        """Whether this source told us when the tag was last published.

        The OCI tag-listing API returns names only, so hardened registries
        usually cannot date their tags. Scoring must treat that as "unknown"
        rather than "ancient", or every Chainguard image is penalised for a
        fact the registry simply did not report.
        """
        return self.last_updated is not None

    @property
    def age_days(self) -> int:
        if not self.last_updated:
            return 365
        delta = datetime.now(tz=self.last_updated.tzinfo) - self.last_updated
        return max(0, delta.days)

    @property
    def is_alpine(self) -> bool:
        return "alpine" in self.tag.lower()

    @property
    def is_distroless(self) -> bool:
        return "distroless" in self.tag.lower() or "distroless" in self.name.lower()

    _HARDENED_MARKERS = ("chainguard", "cgr.dev", "wolfi", "bitnami")

    @property
    def is_hardened_source(self) -> bool:
        """True for images from vendors that specialize in minimal,
        security-hardened bases (Chainguard, Wolfi, Bitnami)."""
        name = self.name.lower()
        return any(marker in name for marker in self._HARDENED_MARKERS)

    @property
    def recently_updated(self) -> bool:
        return self.age_days <= 30
