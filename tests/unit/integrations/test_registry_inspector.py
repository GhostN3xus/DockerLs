"""Digest resolution and config reading, including what must be refused.

The integrity check has teeth: a config blob is addressed by its own
SHA-256, and a registry (or a proxy, or a cache) that answers with different
bytes is not serving the config the manifest points at. The test for that is
the one that matters most here -- without it, every "verified" hardening
fact would rest on trusting whatever the network returned.
"""

from __future__ import annotations

import hashlib
import json

import httpx
import pytest

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.value_objects.tristate import Tristate
from dockerls.integrations.registry.inspector import (
    DOCKER_HUB_REGISTRY,
    RegistryInspector,
    _registry_target,
)

DIGEST = "sha256:" + "1" * 64


def _config_bytes(**config) -> bytes:
    return json.dumps({"os": "linux", "config": config}).encode()


def _digest_of(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _registry(
    *,
    config: bytes,
    config_digest: str | None = None,
    manifest_digest: str = DIGEST,
    layers: list[dict] | None = None,
    index: bool = False,
) -> httpx.MockTransport:
    """A minimal OCI registry: manifest (optionally an index), then a blob."""
    real_config_digest = config_digest or _digest_of(config)
    manifest = {
        "config": {"digest": real_config_digest},
        "layers": layers if layers is not None else [{"size": 100}, {"size": 200}],
    }
    index_body = {
        "manifests": [
            {"digest": "sha256:" + "9" * 64, "platform": {"architecture": "unknown"}},
            {"digest": "sha256:" + "2" * 64, "platform": {"architecture": "amd64", "os": "linux"}},
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if "/blobs/" in path:
            return httpx.Response(200, content=config)
        if "/manifests/" in path:
            reference = path.rsplit("/", 1)[-1]
            headers = {"Docker-Content-Digest": manifest_digest}
            if index and not reference.startswith("sha256:"):
                return httpx.Response(200, json=index_body, headers=headers)
            return httpx.Response(200, json=manifest, headers=headers)
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _inspector(transport: httpx.MockTransport) -> RegistryInspector:
    inspector = RegistryInspector()

    async def client(host: str):
        from dockerls.integrations.registry.oci import OCIRegistryClient

        oci = OCIRegistryClient(host)
        oci._client = httpx.AsyncClient(transport=transport)  # noqa: SLF001 - test injection
        return oci

    inspector._client = client  # type: ignore[method-assign]  # noqa: SLF001
    return inspector


class TestRegistryTargets:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("node", (DOCKER_HUB_REGISTRY, "library/node")),
            ("bitnami/nginx", (DOCKER_HUB_REGISTRY, "bitnami/nginx")),
            ("cgr.dev/chainguard/node", ("cgr.dev", "chainguard/node")),
            ("gcr.io/distroless/nodejs22-debian12", ("gcr.io", "distroless/nodejs22-debian12")),
            ("dhi.io/node", ("dhi.io", "node")),
        ],
    )
    def test_names_split_into_host_and_repository(self, name, expected):
        assert _registry_target(DockerImage(name=name, tag="1")) == expected

    @pytest.mark.parametrize(
        "name",
        [
            "evil.example/../../etc/passwd",
            "UPPER/case",
            "host with spaces/repo",
            "..",
        ],
    )
    def test_malformed_names_resolve_to_no_target(self, name):
        assert _registry_target(DockerImage(name=name, tag="1")) is None


class TestDigestResolution:
    async def test_a_tag_resolves_to_its_manifest_digest(self):
        inspector = _inspector(_registry(config=_config_bytes(User="node")))
        assert await inspector.resolve_digest(DockerImage(name="node", tag="22")) == DIGEST

    async def test_a_second_call_does_not_hit_the_network_again(self):
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(200, json={}, headers={"Docker-Content-Digest": DIGEST})

        inspector = _inspector(httpx.MockTransport(handler))
        image = DockerImage(name="node", tag="22")
        assert await inspector.resolve_digest(image) == DIGEST
        assert await inspector.resolve_digest(image) == DIGEST
        assert len(calls) == 1

    async def test_an_unreachable_registry_resolves_to_nothing(self):
        inspector = _inspector(httpx.MockTransport(lambda request: httpx.Response(500)))
        assert await inspector.resolve_digest(DockerImage(name="node", tag="22")) == ""

    async def test_a_malformed_digest_header_is_ignored(self):
        inspector = _inspector(
            httpx.MockTransport(
                lambda request: httpx.Response(
                    200, json={}, headers={"Docker-Content-Digest": "nope"}
                )
            )
        )
        assert await inspector.resolve_digest(DockerImage(name="node", tag="22")) == ""


class TestConfigInspection:
    async def test_a_non_root_user_is_a_verified_fact(self):
        inspector = _inspector(_registry(config=_config_bytes(User="node")))
        digest, facts = await inspector.inspect(DockerImage(name="node", tag="22"))
        assert digest == DIGEST
        assert facts.runs_as_non_root is Tristate.TRUE
        assert facts.user == "node"
        assert facts.config_verified is True
        assert facts.is_verified("runs_as_non_root")

    async def test_an_unset_user_is_a_determined_root_not_an_unknown(self):
        """An image that sets no USER runs as root; the config *said* that."""
        _, facts = await _inspector(_registry(config=_config_bytes())).inspect(
            DockerImage(name="node", tag="22")
        )
        assert facts.runs_as_non_root is Tristate.FALSE

    @pytest.mark.parametrize("user", ["root", "0", "0:0"])
    async def test_explicit_root_is_false(self, user):
        _, facts = await _inspector(_registry(config=_config_bytes(User=user))).inspect(
            DockerImage(name="node", tag="22")
        )
        assert facts.runs_as_non_root is Tristate.FALSE

    async def test_ports_entrypoint_and_healthcheck_are_read(self):
        config = _config_bytes(
            User="app",
            ExposedPorts={"8080/tcp": {}, "80/tcp": {}, "bogus": {}},
            Entrypoint=["/app/server"],
            Cmd=["--serve"],
            Healthcheck={"Test": ["CMD", "true"]},
        )
        _, facts = await _inspector(_registry(config=config)).inspect(
            DockerImage(name="node", tag="22")
        )
        assert facts.exposed_ports == [80, 8080]
        assert facts.privileged_ports == [80]
        assert facts.entrypoint == ["/app/server"]
        assert facts.cmd == ["--serve"]
        assert facts.has_healthcheck is Tristate.TRUE

    async def test_layers_give_a_verified_count_and_size(self):
        _, facts = await _inspector(
            _registry(config=_config_bytes(User="app"), layers=[{"size": 10}, {"size": 5}])
        ).inspect(DockerImage(name="node", tag="22"))
        assert facts.layer_count == 2
        assert facts.size_bytes == 15

    async def test_a_config_blob_whose_bytes_do_not_match_its_digest_is_discarded(self):
        """Content addressing, actually verified rather than assumed."""
        transport = _registry(config=_config_bytes(User="root"), config_digest="sha256:" + "f" * 64)
        digest, facts = await _inspector(transport).inspect(DockerImage(name="node", tag="22"))
        # The manifest digest still resolved; the config did not survive.
        assert digest == DIGEST
        assert facts.config_verified is False
        assert facts.runs_as_non_root is Tristate.UNKNOWN

    async def test_a_multi_arch_index_follows_the_amd64_child(self):
        inspector = _inspector(_registry(config=_config_bytes(User="node"), index=True))
        digest, facts = await inspector.inspect(DockerImage(name="node", tag="22"))
        assert digest == DIGEST
        assert facts.runs_as_non_root is Tristate.TRUE

    async def test_an_unreachable_registry_produces_no_facts_not_false_ones(self):
        inspector = _inspector(httpx.MockTransport(lambda request: httpx.Response(500)))
        digest, facts = await inspector.inspect(DockerImage(name="node", tag="22"))
        assert digest == ""
        assert facts.config_verified is False
        assert facts.runs_as_non_root is Tristate.UNKNOWN
        assert facts.determined_count == 0
