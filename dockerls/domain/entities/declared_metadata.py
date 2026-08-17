"""What a catalogue *claims* about an image, kept separate from what was measured.

Docker Hardened Images publishes declarative build definitions: which
packages go in, which account the image runs as, when the release goes
end-of-life. That is genuinely useful -- it is more than any registry API
exposes -- but it describes the *intent* of a build, not the bytes that were
published under a tag. A definition can be ahead of the registry, behind it,
or describe a build that failed.

So catalogue claims live in their own type, are always labelled as declared,
and never substitute for a scan. `DockerLs` uses them to discover candidates
and to explain trade-offs; the verdict still comes from resolving the digest
and scanning the image.

The asymmetry in the derived facts below is deliberate and load-bearing: a
declared shell package proves a shell is present, but the *absence* of one
proves nothing -- a busybox-derived base ships `/bin/sh` without ever naming
it as a package. Presence therefore yields TRUE and absence yields UNKNOWN,
never FALSE.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from dockerls.domain.value_objects.tristate import Tristate

#: Packages that put an interactive shell in the image. Presence is proof;
#: absence is not.
SHELL_PACKAGES = frozenset(
    {"bash", "busybox", "dash", "zsh", "ksh", "fish", "toybox", "ash", "shadow"}
)

#: Packages that put a package manager in the image, which is both an
#: attack-surface item and a sign the image is a `-dev` variant.
PACKAGE_MANAGER_PACKAGES = frozenset(
    {"apt", "apt-get", "apk-tools", "dpkg", "rpm", "dnf", "yum", "microdnf", "zypper", "pacman"}
)

#: Compilers, fetchers and inspection utilities. Each one is a capability an
#: attacker inherits if they reach code execution inside the container.
DEBUG_TOOL_PACKAGES = frozenset(
    {
        "curl",
        "wget",
        "git",
        "gcc",
        "g++",
        "clang",
        "make",
        "binutils",
        "strace",
        "ltrace",
        "gdb",
        "netcat",
        "netcat-openbsd",
        "nmap",
        "tcpdump",
        "procps",
        "vim",
        "nano",
        "less",
        "python3",
        "perl",
    }
)


class DeclaredImageMetadata(BaseModel):
    """A catalogue's declaration about one image definition.

    Frozen: a declaration is a record of what a source said at fetch time.
    Mutating it after the fact would make the evidence trail unreliable.
    """

    model_config = ConfigDict(frozen=True)

    #: Which catalogue made the claim, e.g. "Docker Hardened Images".
    catalog: str = ""
    #: Where the claim can be read in full, so a user can audit it.
    definition_url: str = ""
    #: Human name of the definition ("Node.js 22.x").
    display_name: str = ""
    #: Fully-qualified repository the definition publishes to
    #: ("dhi.io/node"). This is what makes a catalogue entry resolvable
    #: against a registry; without it there is no candidate to verify.
    registry_repository: str = ""
    #: "runtime", "dev", "compat", ... -- a `-dev` variant deliberately
    #: carries a shell and a package manager and must not be ranked as if
    #: it were the hardened runtime image.
    variant: str = ""
    #: Account the definition says the image runs as. Empty when unstated.
    run_as_user: str = ""
    #: Declared platforms ("linux/amd64"), used for architecture matching.
    platforms: tuple[str, ...] = ()
    #: ISO dates from the definition; empty when unstated.
    release_date: str = ""
    end_of_life: str = ""
    #: Base OS the definition builds on.
    os_id: str = ""
    os_version: str = ""
    #: Number of packages the definition installs. A real signal of size and
    #: attack surface -- and one no registry API exposes.
    declared_package_count: int | None = None
    entrypoint: tuple[str, ...] = ()
    cmd: tuple[str, ...] = ()
    #: Tags the definition says it publishes, which is what makes a
    #: catalogue entry resolvable against the registry.
    tags: tuple[str, ...] = ()
    #: Package names matched against the sets above, kept so the reason for
    #: a derived fact can be shown rather than asserted.
    shell_packages: tuple[str, ...] = ()
    package_manager_packages: tuple[str, ...] = ()
    debug_tool_packages: tuple[str, ...] = ()

    @property
    def declared_non_root(self) -> Tristate:
        """Whether the definition says the image runs as a non-root account.

        `run-as: root` is an explicit FALSE. An empty `run-as` is UNKNOWN,
        not FALSE: the definition simply did not say, and the OCI config of
        the built image is the authority either way.
        """
        if not self.run_as_user:
            return Tristate.UNKNOWN
        return Tristate.of(self.run_as_user.lower() not in ("root", "0"))

    @property
    def declared_has_shell(self) -> Tristate:
        return Tristate.TRUE if self.shell_packages else Tristate.UNKNOWN

    @property
    def declared_has_package_manager(self) -> Tristate:
        return Tristate.TRUE if self.package_manager_packages else Tristate.UNKNOWN

    @property
    def declared_has_debug_tools(self) -> Tristate:
        return Tristate.TRUE if self.debug_tool_packages else Tristate.UNKNOWN

    @property
    def is_dev_variant(self) -> bool:
        """A development variant ships build tooling by design.

        Ranked against runtime variants without this distinction, a `-dev`
        image looks like just another candidate from a hardened catalogue.
        """
        return "dev" in self.variant.lower().split("-") or self.variant.lower().endswith("dev")
