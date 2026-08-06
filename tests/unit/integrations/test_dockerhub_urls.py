from __future__ import annotations

from dockerls.integrations.dockerhub.urls import (
    build_dockerhub_url,
    build_tag_api_url,
    split_repository,
)


class TestSplitRepository:
    def test_official_image_uses_library_namespace(self):
        assert split_repository("node") == ("library", "node")

    def test_third_party_image(self):
        assert split_repository("bitnami/node") == ("bitnami", "node")

    def test_explicit_docker_io_prefix_is_stripped(self):
        assert split_repository("docker.io/library/node") == ("library", "node")

    def test_foreign_registry_is_not_dockerhub(self):
        assert split_repository("ghcr.io/org/app") is None
        assert split_repository("cgr.dev/chainguard/node") is None
        assert split_repository("registry.internal:5000/team/app") is None

    def test_digest_suffix_is_stripped(self):
        assert split_repository("node@sha256:" + "a" * 64) == ("library", "node")

    def test_empty_is_none(self):
        assert split_repository("") is None
        assert split_repository("   ") is None


class TestBuildDockerHubUrl:
    def test_official_image_url(self):
        url = build_dockerhub_url("node", "26.7-slim")
        assert url == "https://hub.docker.com/_/node?tab=tags&name=26.7-slim"

    def test_third_party_url(self):
        url = build_dockerhub_url("bitnami/node", "22-debian-12")
        assert url == "https://hub.docker.com/r/bitnami/node/tags?name=22-debian-12"

    def test_tag_is_percent_encoded(self):
        url = build_dockerhub_url("node", "22/alpine")
        assert "22%2Falpine" in url
        # The encoded tag must not introduce an extra path segment.
        assert url.count("?") == 1

    def test_foreign_registry_yields_no_url(self):
        assert build_dockerhub_url("ghcr.io/org/app", "v1") == ""


class TestBuildTagApiUrl:
    def test_official_image_api_url(self):
        url = build_tag_api_url("node", "22-alpine")
        assert url == "https://hub.docker.com/v2/repositories/library/node/tags/22-alpine"

    def test_third_party_api_url(self):
        url = build_tag_api_url("bitnami/node", "22")
        assert url == "https://hub.docker.com/v2/repositories/bitnami/node/tags/22"

    def test_foreign_registry_yields_no_url(self):
        assert build_tag_api_url("ghcr.io/org/app", "v1") == ""
