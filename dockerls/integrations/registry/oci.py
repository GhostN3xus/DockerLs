from __future__ import annotations

import re
from typing import Any

import httpx
from loguru import logger

# Cosign and friends publish their signatures, attestations and SBOMs as
# ordinary tags in the same repository. They are not runnable images, so
# they must never reach the scan pipeline.
_ARTIFACT_TAG = re.compile(
    r"""
    ^sha256[-:]            # cosign artifacts: sha256-<digest>.sig/.att/.sbom
  | \.(sig|att|sbom)$
  | ^deprecated-public-image-
    """,
    re.VERBOSE,
)

# Single-architecture aliases of a multi-arch tag ("16-amd64"). Scanning them
# adds duplicates of a tag we already have.
_ARCH_SUFFIX = re.compile(r"-(amd64|arm64|arm|armv[567]|386|ppc64le|s390x|riscv64|mips64le|wasm)$")

# Provenance-pinned variants -- either suffixed ("debug-nonroot-165b5d63...")
# or a bare commit hash -- point at the same image as their base tag.
# Distroless publishes dozens per release; unfiltered they crowd out every
# distinct image in the listing.
_COMMIT_TAG = re.compile(r"(-[0-9a-f]{32,}$|^[0-9a-f]{32,}$)")


def is_runnable_tag(tag: str) -> bool:
    """True for tags that name a distinct image a user would actually pull."""
    if not tag or _ARTIFACT_TAG.search(tag):
        return False
    if _COMMIT_TAG.search(tag):
        return False
    return not _ARCH_SUFFIX.search(tag)


def parse_www_authenticate(header: str) -> tuple[str, dict[str, str]]:
    """Split a `Bearer realm="...",service="...",scope="..."` challenge into
    (realm, params)."""
    if not header.lower().startswith("bearer"):
        return "", {}
    params = dict(re.findall(r'(\w+)="([^"]*)"', header))
    return params.pop("realm", ""), params


class OCIRegistryClient:
    """Minimal OCI Distribution v2 client for listing tags.

    Implements only the anonymous pull-scope token dance that public
    registries use: request the endpoint, and if it answers 401 with a
    Bearer challenge, fetch a token from the advertised realm and retry.
    """

    def __init__(self, host: str, timeout: int = 30):
        self._host = host
        self._timeout = timeout

    @property
    def host(self) -> str:
        return self._host

    async def _token(self, client: httpx.AsyncClient, challenge: str) -> str:
        realm, params = parse_www_authenticate(challenge)
        if not realm:
            return ""
        resp = await client.get(realm, params=params)
        resp.raise_for_status()
        data = resp.json()
        # Registries disagree on the field name; GCR/ECR use access_token.
        token: str = data.get("token") or data.get("access_token") or ""
        return token

    async def list_tags(self, repository: str) -> dict[str, Any] | None:
        """Return the raw `/v2/<repository>/tags/list` payload, or None when
        the repository does not exist or cannot be reached."""
        url = f"https://{self._host}/v2/{repository}/tags/list"
        try:
            async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=True) as client:
                resp = await client.get(url)
                if resp.status_code == 401:
                    token = await self._token(client, resp.headers.get("WWW-Authenticate", ""))
                    if not token:
                        logger.warning(f"No anonymous token available for {self._host}")
                        return None
                    resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})

                if resp.status_code == 404:
                    logger.info(f"Repository not found: {self._host}/{repository}")
                    return None
                resp.raise_for_status()
                payload: dict[str, Any] = resp.json()
                return payload
        except (httpx.HTTPError, ValueError) as e:
            logger.warning(f"Tag listing failed for {self._host}/{repository}: {e}")
            return None
