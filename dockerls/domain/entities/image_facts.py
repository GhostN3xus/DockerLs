"""What was actually determined about an image, and who determined it.

This is the evidence record that the hardening and attack-surface analyses
read from. Three rules shape it, and all three exist because the alternative
is a tool that reports confident nonsense:

1. **Every fact is three-valued.** A property that could not be determined
   is UNKNOWN, and UNKNOWN never earns credit in either direction.

2. **Every fact records its source.** "Runs as non-root" carries a very
   different weight when it comes from the OCI config of a resolved digest
   than when a vendor's build definition claims it. Both are recorded; only
   one is verification.

3. **Nothing is inferred from a name.** An image called `distroless` is not
   evidence of anything. The facts here come from the registry, from the
   scanner, or from a catalogue declaration -- never from a substring.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from dockerls.domain.value_objects.tristate import Tristate


class EvidenceSource(StrEnum):
    """Where a fact came from, ordered by how much it is worth.

    `REGISTRY` and `SCANNER` are measurements of the published artifact.
    `CATALOG` is a vendor's declaration about a build -- useful, auditable,
    and not a measurement. The distinction is carried all the way to the
    JSON output so a consumer can apply its own policy to declared facts.
    """

    #: OCI image config fetched from the registry at a resolved digest.
    REGISTRY = "registry"
    #: Package inventory observed by a vulnerability scanner.
    SCANNER = "scanner"
    #: A build definition published by the image's vendor.
    CATALOG = "catalog"
    #: Nothing determined this.
    NONE = "none"


class HardeningFacts(BaseModel):
    """Per-image evidence, with the origin of each determined fact.

    Defaults are all UNKNOWN/empty on purpose: an image nobody inspected
    must read as "nothing is known", never as "nothing was found".
    """

    # --- Privilege -------------------------------------------------------
    #: Whether the image's *default* execution account is not root. An image
    #: that sets no USER runs as root, so an empty `User` in a config that
    #: was actually fetched is a determined FALSE, not an unknown.
    runs_as_non_root: Tristate = Tristate.UNKNOWN
    #: The configured user string, verbatim ("node", "65532", "" for unset).
    user: str = ""

    # --- Contents --------------------------------------------------------
    has_shell: Tristate = Tristate.UNKNOWN
    has_package_manager: Tristate = Tristate.UNKNOWN
    has_debug_tools: Tristate = Tristate.UNKNOWN
    #: SUID/SGID binaries cannot be determined without unpacking the
    #: filesystem, which this tool does not do. Kept as a declared field so
    #: the gap is visible rather than silently absent.
    has_setuid: Tristate = Tristate.UNKNOWN
    #: Packages the image is known to contain. None when nothing counted
    #: them -- which is different from zero.
    package_count: int | None = None

    # --- Runtime configuration -------------------------------------------
    #: Ports the image declares. Empty list means "declared none" only when
    #: the config was fetched; `ports_known` says which case this is.
    exposed_ports: list[int] = Field(default_factory=list)
    has_healthcheck: Tristate = Tristate.UNKNOWN
    entrypoint: list[str] = Field(default_factory=list)
    cmd: list[str] = Field(default_factory=list)

    # --- Composition -----------------------------------------------------
    layer_count: int | None = None
    size_bytes: int | None = None
    os_family: str = ""

    #: fact name -> the source that determined it. A fact absent from this
    #: mapping was never determined by anything.
    evidence: dict[str, EvidenceSource] = Field(default_factory=dict)

    #: True once an OCI config was actually fetched, which is what makes
    #: "no ports declared" and "no USER set" readable as facts.
    config_verified: bool = False

    #: Places where a catalogue's declaration and the published image
    #: disagree, in the reader's terms. This is the single most valuable
    #: output of comparing declared metadata against a measurement, and it
    #: is surfaced rather than resolved silently: a vendor claiming an image
    #: runs unprivileged while its config says root is exactly the kind of
    #: thing a security tool exists to notice.
    conflicts: list[str] = Field(default_factory=list)

    def source_of(self, fact: str) -> EvidenceSource:
        return self.evidence.get(fact, EvidenceSource.NONE)

    def is_verified(self, fact: str) -> bool:
        """Whether `fact` was measured rather than declared.

        The ranking layer uses this to keep a vendor's claim from carrying
        the same weight as a registry measurement.
        """
        return self.source_of(fact) in (EvidenceSource.REGISTRY, EvidenceSource.SCANNER)

    @property
    def ports_known(self) -> bool:
        return self.config_verified or bool(self.exposed_ports)

    @property
    def privileged_ports(self) -> list[int]:
        """Declared ports below 1024.

        Binding one of these traditionally requires elevated privileges or
        an explicit capability, so an image declaring them is telling us
        something about how it expects to be run.
        """
        return [port for port in self.exposed_ports if port < 1024]

    @property
    def determined_count(self) -> int:
        """How many facts anything actually determined.

        Reported alongside every derived score, because a score computed
        over two facts and a score computed over ten are not comparable and
        must not be presented as if they were.
        """
        return len(self.evidence)
