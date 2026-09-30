"""Pinning a tag to the manifest of one platform.

The properties under test are the ones that make an "immutable reference"
worth anything: the index digest is never confused with the platform
manifest's, a platform that is not offered is refused rather than replaced by
another, served bytes must hash to the digest that named them, and a tag is
resolved once per run so a tag that moves cannot re-associate a scan.
"""

from __future__ import annotations

import hashlib
import json

import httpx
import pytest

from dockerls.domain.value_objects.measured_identity import IdentityStatus
from dockerls.domain.value_objects.platform import Platform
from dockerls.integrations.registry.inspector import RegistryInspector
from dockerls.integrations.registry.oci import OCIRegistryClient


def _digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _body(document: dict) -> bytes:
    return json.dumps(document, sort_keys=True).encode()


CHILD_AMD64 = "sha256:" + "a" * 64
CHILD_ARM64 = "sha256:" + "b" * 64
CHILD_ATTESTATION = "sha256:" + "c" * 64


def _index(*entries: tuple[str, str, str, str]) -> dict:
    return {
        "schemaVersion": 2,
        "manifests": [
            {
                "digest": digest,
                "platform": {"os": os_name, "architecture": arch, **({"variant": v} if v else {})},
            }
            for digest, os_name, arch, v in entries
        ],
    }


STANDARD_INDEX = _index(
    (CHILD_AMD64, "linux", "amd64", ""),
    (CHILD_ARM64, "linux", "arm64", "v8"),
    (CHILD_ATTESTATION, "unknown", "unknown", ""),
)


class FakeRegistry:
    """Serves manifests by tag or digest; `tags` can be repointed mid-test."""

    def __init__(self) -> None:
        self.tags: dict[str, bytes] = {}
        self.by_digest: dict[str, bytes] = {}
        self.requests: list[str] = []
        self.header_override: str | None = None
        self.online = True

    def publish(self, tag: str, document: dict) -> str:
        payload = _body(document)
        digest = _digest(payload)
        self.tags[tag] = payload
        self.by_digest[digest] = payload
        return digest

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request.url.path)
            if not self.online:
                return httpx.Response(500)
            if "/manifests/" not in request.url.path:
                return httpx.Response(404)
            reference = request.url.path.rsplit("/", 1)[-1]
            payload = self.tags.get(reference) or self.by_digest.get(reference)
            if payload is None:
                return httpx.Response(404)
            digest = self.header_override or _digest(payload)
            return httpx.Response(200, content=payload, headers={"Docker-Content-Digest": digest})

        return httpx.MockTransport(handler)


def _inspector(registry: FakeRegistry) -> RegistryInspector:
    inspector = RegistryInspector(max_attempts=1, backoff_base=0.0)
    transport = registry.transport()

    async def client(host: str):
        oci = OCIRegistryClient(host)
        oci._client = httpx.AsyncClient(transport=transport)  # noqa: SLF001 - test injection
        return oci

    inspector._client = client  # type: ignore[method-assign]  # noqa: SLF001
    return inspector


async def _resolve(inspector, tag="22", platform="linux/amd64", digest=""):
    return await inspector.resolve_identity(
        "node", tag, digest=digest, platform=Platform.parse(platform)
    )


class TestIndexVersusPlatformManifest:
    async def test_the_index_digest_and_the_manifest_digest_are_different_things(self):
        registry = FakeRegistry()
        index_digest = registry.publish("22", STANDARD_INDEX)

        identity = await _resolve(_inspector(registry))

        assert identity.status is IdentityStatus.CONFIRMED
        assert identity.index_digest == index_digest
        assert identity.manifest_digest == CHILD_AMD64
        assert identity.index_digest != identity.manifest_digest
        assert identity.resolved_reference == f"node@{CHILD_AMD64}"

    async def test_other_platforms_resolve_to_their_own_manifest(self):
        registry = FakeRegistry()
        registry.publish("22", STANDARD_INDEX)
        inspector = _inspector(registry)

        amd64 = await _resolve(inspector, platform="linux/amd64")
        arm64 = await _resolve(inspector, platform="linux/arm64")

        assert (amd64.manifest_digest, arm64.manifest_digest) == (CHILD_AMD64, CHILD_ARM64)
        assert amd64.index_digest == arm64.index_digest

    async def test_a_platform_the_index_does_not_offer_is_refused_not_substituted(self):
        registry = FakeRegistry()
        registry.publish("22", STANDARD_INDEX)

        identity = await _resolve(_inspector(registry), platform="linux/s390x")

        assert identity.status is IdentityStatus.PLATFORM_MISMATCH
        assert not identity.confirmed
        assert identity.manifest_digest == ""
        assert "linux/amd64" in identity.limitation and "linux/s390x" in identity.limitation

    async def test_attestation_manifests_are_never_candidates(self):
        registry = FakeRegistry()
        registry.publish("22", _index((CHILD_ATTESTATION, "unknown", "unknown", "")))

        identity = await _resolve(_inspector(registry))

        assert identity.status is IdentityStatus.PLATFORM_MISMATCH

    async def test_several_variants_are_disambiguated_by_the_architecture_default(self):
        registry = FakeRegistry()
        v6, v7 = "sha256:" + "6" * 64, "sha256:" + "7" * 64
        registry.publish("22", _index((v6, "linux", "arm", "v6"), (v7, "linux", "arm", "v7")))

        identity = await _resolve(_inspector(registry), platform="linux/arm")
        explicit = await _resolve(_inspector(registry), platform="linux/arm/v6")

        assert identity.manifest_digest == v7
        assert explicit.manifest_digest == v6

    async def test_an_ambiguous_choice_is_refused_rather_than_guessed(self):
        registry = FakeRegistry()
        a, b = "sha256:" + "1" * 64, "sha256:" + "2" * 64
        registry.publish("22", _index((a, "linux", "riscv64", "x1"), (b, "linux", "riscv64", "x2")))

        identity = await _resolve(_inspector(registry), platform="linux/riscv64")

        assert identity.status is IdentityStatus.PLATFORM_MISMATCH
        assert "variant" in identity.limitation


class TestSingleManifests:
    @staticmethod
    def _single(registry: FakeRegistry, *, arch: str = "amd64") -> str:
        config = _body({"os": "linux", "architecture": arch, "config": {}})
        registry.by_digest[_digest(config)] = config
        manifest = {"config": {"digest": _digest(config)}, "layers": []}
        return registry.publish("1", manifest)

    async def test_a_single_manifest_is_confirmed_by_its_own_config(self):
        registry = FakeRegistry()
        digest = self._single(registry)
        inspector = _inspector(registry)
        # the blob endpoint is not part of FakeRegistry.publish -- serve it
        inspector._client = self._with_blobs(registry)  # type: ignore[method-assign]  # noqa: SLF001

        identity = await _resolve(inspector, tag="1")

        assert identity.status is IdentityStatus.CONFIRMED
        assert identity.index_digest == ""
        assert identity.manifest_digest == digest

    async def test_a_single_manifest_for_another_platform_is_a_mismatch(self):
        registry = FakeRegistry()
        self._single(registry, arch="arm64")
        inspector = _inspector(registry)
        inspector._client = self._with_blobs(registry)  # type: ignore[method-assign]  # noqa: SLF001

        identity = await _resolve(inspector, tag="1", platform="linux/amd64")

        assert identity.status is IdentityStatus.PLATFORM_MISMATCH
        assert "linux/arm64" in identity.limitation

    @staticmethod
    def _with_blobs(registry: FakeRegistry):
        transport_handler = registry.transport()

        def handler(request: httpx.Request) -> httpx.Response:
            if "/blobs/" in request.url.path:
                payload = registry.by_digest.get(request.url.path.rsplit("/", 1)[-1])
                return httpx.Response(200, content=payload) if payload else httpx.Response(404)
            return transport_handler.handle_request(request)

        async def client(host: str):
            oci = OCIRegistryClient(host)
            oci._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))  # noqa: SLF001
            return oci

        return client


class TestIntegrity:
    async def test_bytes_that_do_not_hash_to_the_pinned_digest_are_refused(self):
        registry = FakeRegistry()
        registry.publish("22", STANDARD_INDEX)
        wanted = "sha256:" + "d" * 64
        registry.by_digest[wanted] = registry.tags["22"]  # someone else's bytes under this name

        identity = await _resolve(_inspector(registry), digest=wanted)

        assert not identity.confirmed
        assert "do not hash" in identity.limitation

    async def test_a_digest_header_that_disagrees_with_the_content_is_refused(self):
        registry = FakeRegistry()
        registry.publish("22", STANDARD_INDEX)
        registry.header_override = "sha256:" + "e" * 64

        identity = await _resolve(_inspector(registry))

        assert not identity.confirmed
        assert "do not hash" in identity.limitation

    async def test_an_unreachable_registry_leaves_the_identity_unresolved(self):
        registry = FakeRegistry()
        registry.online = False

        identity = await _resolve(_inspector(registry))

        assert identity.status is IdentityStatus.UNRESOLVED
        assert identity.resolved_reference == ""
        assert identity.limitation

    async def test_an_unreachable_registry_still_names_a_user_supplied_digest(self):
        registry = FakeRegistry()
        registry.online = False
        pinned = "sha256:" + "f" * 64

        identity = await _resolve(_inspector(registry), digest=pinned)

        # The bytes are named by the user, but nothing verified their platform.
        assert identity.status is IdentityStatus.DIGEST_ONLY
        assert not identity.confirmed

    async def test_a_malformed_name_is_never_sent_to_a_registry(self):
        registry = FakeRegistry()
        inspector = _inspector(registry)

        identity = await inspector.resolve_identity(
            "evil.example/../../etc/passwd", "1", platform=Platform.parse("linux/amd64")
        )

        assert identity.status is IdentityStatus.UNRESOLVED
        assert registry.requests == []


class TestResolvedOncePerRun:
    async def test_a_tag_that_moves_mid_run_keeps_its_first_answer(self):
        registry = FakeRegistry()
        first_index = registry.publish("22", STANDARD_INDEX)
        inspector = _inspector(registry)

        before = await _resolve(inspector)
        moved = _index(
            ("sha256:" + "9" * 64, "linux", "amd64", ""),
        )
        registry.publish("22", moved)
        after = await _resolve(inspector)

        assert before is after
        assert after.index_digest == first_index
        assert after.manifest_digest == CHILD_AMD64

    async def test_concurrent_resolutions_share_one_request(self):
        import asyncio

        registry = FakeRegistry()
        registry.publish("22", STANDARD_INDEX)
        inspector = _inspector(registry)

        results = await asyncio.gather(*(_resolve(inspector) for _ in range(10)))

        assert len({r.manifest_digest for r in results}) == 1
        assert len([p for p in registry.requests if "/manifests/" in p]) == 1


@pytest.mark.parametrize("platform", ["linux/amd64", "linux/arm64"])
async def test_inspect_reads_the_config_of_the_requested_platform(platform):
    """Facts measured on one manifest must not be attributed to another: the
    old code hard-coded linux/amd64 when following an index."""
    registry = FakeRegistry()
    configs = {}
    for digest, arch in ((CHILD_AMD64, "amd64"), (CHILD_ARM64, "arm64")):
        config = _body({"os": "linux", "architecture": arch, "config": {"User": f"user-{arch}"}})
        configs[_digest(config)] = config
        manifest = {"config": {"digest": _digest(config)}, "layers": []}
        registry.by_digest[digest] = _body(manifest)
    registry.publish("22", STANDARD_INDEX)
    served = registry.transport()

    def handler(request: httpx.Request) -> httpx.Response:
        if "/blobs/" in request.url.path:
            return httpx.Response(200, content=configs[request.url.path.rsplit("/", 1)[-1]])
        response = served.handle_request(request)
        if "/manifests/sha256:" in request.url.path:
            # child manifests are served under the digest the index names, so
            # the served bytes cannot hash to it: use the plain payload
            payload = registry.by_digest[request.url.path.rsplit("/", 1)[-1]]
            return httpx.Response(200, content=payload, headers={"Docker-Content-Digest": ""})
        return response

    inspector = RegistryInspector(max_attempts=1, backoff_base=0.0)

    async def client(host: str):
        oci = OCIRegistryClient(host)
        oci._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))  # noqa: SLF001
        return oci

    inspector._client = client  # type: ignore[method-assign]  # noqa: SLF001

    from dockerls.domain.entities.image import DockerImage

    _, facts = await inspector.inspect(
        DockerImage(name="node", tag="22"), platform=Platform.parse(platform)
    )

    assert facts.user == f"user-{platform.split('/')[1]}"
