from __future__ import annotations

from urllib.parse import quote

HUB_WEB_BASE = "https://hub.docker.com"
HUB_API_BASE = "https://hub.docker.com/v2"


def _is_registry_host(segment: str) -> bool:
    """A leading path segment is a registry host (ghcr.io, cgr.dev,
    registry.internal:5000) rather than a Docker Hub namespace when it
    carries a dot or a port."""
    return "." in segment or ":" in segment


def split_repository(image: str) -> tuple[str, str] | None:
    """Split a Docker Hub image name into (namespace, repository).

    Official images ("node") map to the implicit "library" namespace, which
    is what the Hub API expects. Returns None for references that are not
    hosted on Docker Hub (e.g. "ghcr.io/org/app", "cgr.dev/chainguard/node")
    so callers never build a link that would 404.
    """
    name = image.strip().strip("/")
    if not name:
        return None

    # Strip any tag/digest suffix that leaked into the name.
    if "@" in name:
        name = name.split("@", 1)[0]

    parts = name.split("/")
    if _is_registry_host(parts[0]) and parts[0] not in ("docker.io", "index.docker.io"):
        return None
    if parts[0] in ("docker.io", "index.docker.io"):
        parts = parts[1:]

    if not parts or not parts[0]:
        return None
    if len(parts) == 1:
        return "library", parts[0]
    if len(parts) == 2:
        return parts[0], parts[1]
    return None


def build_dockerhub_url(image: str, tag: str) -> str:
    """Return the canonical Docker Hub web URL for `image`:`tag`.

    Official images live under the `_/<repo>` path and expose their tags via
    a query parameter; everything else lives under `r/<ns>/<repo>/tags`.
    Returns "" when the image is not on Docker Hub.
    """
    split = split_repository(image)
    if split is None:
        return ""
    namespace, repo = split
    safe_tag = quote(tag, safe="")

    if namespace == "library":
        return f"{HUB_WEB_BASE}/_/{quote(repo, safe='')}?tab=tags&name={safe_tag}"
    ns = quote(namespace, safe="")
    return f"{HUB_WEB_BASE}/r/{ns}/{quote(repo, safe='')}/tags?name={safe_tag}"


def build_tag_api_url(image: str, tag: str) -> str:
    """Return the Hub API endpoint that confirms a tag actually exists."""
    split = split_repository(image)
    if split is None:
        return ""
    namespace, repo = split
    return (
        f"{HUB_API_BASE}/repositories/{quote(namespace, safe='')}/"
        f"{quote(repo, safe='')}/tags/{quote(tag, safe='')}"
    )
