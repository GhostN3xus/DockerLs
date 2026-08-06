from __future__ import annotations

from urllib.parse import quote

from dockerls.integrations.dockerhub.urls import build_dockerhub_url

# Browsable catalogue pages for the hardened sources. Neither registry
# exposes a per-tag web page, so these link to the image's catalogue entry.
_HARDENED_HOSTS = {
    "cgr.dev": "https://images.chainguard.dev/directory/image/{repo}/versions",
    "gcr.io": "https://console.cloud.google.com/gcr/images/{namespace}/global/{repo}",
}


def source_url(image_name: str, tag: str) -> str:
    """Return a human-browsable URL for `image_name`:`tag` at its source.

    Docker Hub images get their exact tag-filtered Hub URL; hardened
    registries get their catalogue page. Returns "" when the source has no
    known web presence.
    """
    hub = build_dockerhub_url(image_name, tag)
    if hub:
        return hub

    parts = image_name.split("/")
    if len(parts) < 3:
        return ""
    host, namespace, repo = parts[0], parts[1], "/".join(parts[2:])
    template = _HARDENED_HOSTS.get(host)
    if not template:
        return ""
    return template.format(
        namespace=quote(namespace, safe=""),
        repo=quote(repo, safe=""),
    )
