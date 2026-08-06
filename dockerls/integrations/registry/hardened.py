from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from loguru import logger

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from dockerls.integrations.registry.oci import OCIRegistryClient, is_runnable_tag

CHAINGUARD = "Chainguard"
DISTROLESS = "Distroless"


class HardenedRepository(ImageRepositoryInterface):
    """Base for free, security-hardened image sources exposed over the OCI
    Distribution API.

    These registries publish tag names only -- no size, no timestamps -- so
    the resulting `DockerImage` carries the minimum the scan pipeline needs
    and leaves the rest unset rather than inventing values.
    """

    source: str = ""
    host: str = ""
    namespace: str = ""
    # Query name -> repository name, where the upstream project names an
    # image differently from the Docker Hub convention users type.
    aliases: dict[str, str] = {}

    def __init__(self, timeout: int = 30):
        self._client = OCIRegistryClient(self.host, timeout=timeout)

    def repository_for(self, image_name: str) -> str | None:
        """Map a user's query ("node") onto this source's repository path.

        Returns None for references that already name a different registry,
        so `dockerls recommend ghcr.io/org/app` never fans out to Chainguard.
        """
        name = image_name.strip().strip("/")
        if not name or "/" in name or ":" in name:
            return None
        return f"{self.namespace}/{self.aliases.get(name, name)}"

    def _full_name(self, repository: str) -> str:
        return f"{self.host}/{repository}"

    def _build_image(self, repository: str, tag: str, payload: dict[str, Any]) -> DockerImage:
        return DockerImage(
            name=self._full_name(repository),
            tag=tag,
            source=self.source,
            is_official=True,
        )

    def _runnable_tags(self, payload: dict[str, Any]) -> list[str]:
        return [t for t in (payload.get("tags") or []) if is_runnable_tag(t)]

    async def search_tags(self, image_name: str, limit: int = 100) -> list[DockerImage]:
        repository = self.repository_for(image_name)
        if repository is None:
            return []

        payload = await self._client.list_tags(repository)
        if payload is None:
            return []

        # Build first, then rank: a source that dates its tags (GCR) must be
        # ordered newest-first, or a lexical sort surfaces nodejs:10 ahead of
        # nodejs:22 and the tool recommends a years-old runtime.
        images = [
            self._build_image(repository, tag, payload) for tag in self._runnable_tags(payload)
        ]
        images.sort(key=_image_rank)
        selected = images[:limit]
        logger.info(f"{self.source}: {len(selected)} usable tags for {self._full_name(repository)}")
        return selected

    async def get_image_metadata(self, image_name: str, tag: str) -> DockerImage | None:
        repository = self.repository_for(image_name)
        if repository is None:
            return None
        payload = await self._client.list_tags(repository)
        if payload is None or tag not in (payload.get("tags") or []):
            return None
        return self._build_image(repository, tag, payload)

    async def tag_exists(self, image_name: str, tag: str) -> bool | None:
        """A tag returned by a live listing is confirmed by construction."""
        repository = self.repository_for(image_name)
        if repository is None:
            return None
        payload = await self._client.list_tags(repository)
        if payload is None:
            return None
        return tag in (payload.get("tags") or [])


_PREFERRED_TAGS = ("latest", "latest-dev", "nonroot", "debug", "static")


def _image_rank(image: DockerImage) -> tuple[int, str, float, str]:
    """Order: conventional entrypoints first, then newest published, then
    name. Undated tags fall back to name ordering rather than pretending to
    be either new or old."""
    if image.tag in _PREFERRED_TAGS:
        return (0, f"{_PREFERRED_TAGS.index(image.tag):02d}", 0.0, image.tag)
    published = -image.last_updated.timestamp() if image.last_updated else 0.0
    return (1, "", published, image.tag)


class ChainguardRepository(HardenedRepository):
    """Chainguard's free tier (cgr.dev/chainguard/<image>).

    The free catalogue tracks only the moving tags -- `latest`,
    `latest-dev` and friends; pinned version tags are a paid feature -- so a
    handful of results here is the expected outcome, not a failure.
    """

    source = CHAINGUARD
    host = "cgr.dev"
    namespace = "chainguard"
    aliases = {
        "nodejs": "node",
        "python3": "python",
        "golang": "go",
        "openjdk": "jdk",
    }


class DistrolessRepository(HardenedRepository):
    """Google's Distroless images (gcr.io/distroless/<image>)."""

    source = DISTROLESS
    host = "gcr.io"
    namespace = "distroless"
    aliases = {
        "node": "nodejs",
        "python": "python3",
        "golang": "static",
        "go": "static",
    }

    def _build_image(self, repository: str, tag: str, payload: dict[str, Any]) -> DockerImage:
        image = super()._build_image(repository, tag, payload)
        # GCR uniquely returns a manifest map with upload timestamps and
        # sizes, so distroless images can be dated instead of guessed at.
        meta = _gcr_manifest_for_tag(payload, tag)
        if not meta:
            return image
        dated: DockerImage = image.model_copy(update=meta)
        return dated


def _gcr_manifest_for_tag(payload: dict[str, Any], tag: str) -> dict[str, Any]:
    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        return {}
    for digest, entry in manifest.items():
        if not isinstance(entry, dict) or tag not in (entry.get("tag") or []):
            continue
        update: dict[str, Any] = {"digest": digest}
        size = entry.get("imageSizeBytes")
        if size is not None:
            with_int = _safe_int(size)
            if with_int is not None:
                update["size_bytes"] = with_int
        uploaded = _safe_int(entry.get("timeUploadedMs"))
        # GCR reports a sentinel far-past timeCreatedMs for many images;
        # timeUploadedMs is the field that reflects reality.
        if uploaded and uploaded > 0:
            update["last_updated"] = datetime.fromtimestamp(uploaded / 1000, tz=UTC)
        return update
    return {}


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
