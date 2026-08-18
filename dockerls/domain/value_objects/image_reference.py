"""Where an image reference says it will make this process connect.

The SSRF policy already guards the registry inspector, but the inspector is
not the only thing a reference reaches the network with. `trivy image X` and
`grype X` **pull X themselves**, over a socket this process opened, from a
host named inside the reference. A reference of
`169.254.169.254/latest:v1` therefore aimed the scanner's own pull at the
cloud metadata endpoint while the guard watched a request that was never
made -- the guard was on one door of a building with two.

Extracting the host is the pure half of closing that, and it lives here for
the same reason `NetworkPolicy` does: the rule can then be tested against
every reference shape without a network, and the resolution stays in
infrastructure where the sockets are.

The rule is Docker's own: the first path component is a registry host only
when it carries a dot or a colon, or is exactly `localhost`. Everything else
is a namespace on Docker Hub. `localhost` is the case a naive
dot-or-colon test misses, and it is precisely the one an attacker wants.
"""

from __future__ import annotations

#: Registry hosts that mean Docker Hub. Contacting them is the default
#: behaviour of every reference, so they are not host-qualified for policy.
_DOCKER_HUB_HOSTS = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io"})


def registry_host_of(reference: str) -> str:
    """The registry host named in `reference`, or "" when it means Docker Hub.

    Returns the host **as written**, port included, because that is what an
    allowlist entry and a policy explanation have to match.
    """
    name = reference.strip()
    if not name:
        return ""
    # A digest or tag suffix never contains the registry, and dropping it
    # first stops `node@sha256:...` from looking port-qualified.
    name = name.split("@", 1)[0]
    head = name.split("/", 1)[0]
    if "/" not in name:
        return ""
    if not is_registry_host(head):
        return ""
    return "" if head.lower() in _DOCKER_HUB_HOSTS else head


def is_registry_host(segment: str) -> bool:
    """Whether a leading path component names a registry rather than a namespace.

    `localhost` is included explicitly: it carries neither a dot nor a port,
    so a dot-or-colon test reads `localhost/evil` as the Docker Hub user
    "localhost" and lets the pull through to a service on this machine.
    """
    return "." in segment or ":" in segment or segment.lower() == "localhost"
