"""Platform parsing, and the matching rule that decides which manifest of an
index is *the* image -- never "the first one that looks usable"."""

from __future__ import annotations

import pytest

from dockerls.domain.value_objects.platform import (
    DEFAULT_PLATFORM,
    InvalidPlatformError,
    Platform,
    parse_platform,
)


class TestParsing:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("linux/amd64", "linux/amd64"),
            ("LINUX/ARM64", "linux/arm64"),
            ("linux/arm64/v8", "linux/arm64/v8"),
            ("linux/x86_64", "linux/amd64"),
            ("linux/aarch64", "linux/arm64"),
            (" linux/arm/v7 ", "linux/arm/v7"),
        ],
    )
    def test_valid_platforms_are_normalised(self, text, expected):
        assert str(Platform.parse(text)) == expected

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "linux",
            "linux/",
            "/amd64",
            "linux/amd64/v8/extra",
            "linux/amd64; rm -rf /",
            "linux/amd64 --evil",
            "linux//amd64",
            "-linux/amd64",
            "linux/$(id)",
            "linux/amd\n64",
        ],
    )
    def test_malformed_platforms_are_refused(self, text):
        with pytest.raises(InvalidPlatformError):
            Platform.parse(text)

    def test_nothing_requested_means_the_explicit_default(self):
        assert parse_platform(None) == DEFAULT_PLATFORM
        assert parse_platform("  ") == DEFAULT_PLATFORM
        assert str(DEFAULT_PLATFORM) == "linux/amd64"


class TestMatching:
    def test_a_request_without_variant_accepts_any_variant(self):
        assert Platform.parse("linux/arm64").satisfied_by(Platform.parse("linux/arm64/v8"))

    def test_a_request_with_a_variant_requires_it(self):
        assert not Platform.parse("linux/arm/v7").satisfied_by(Platform.parse("linux/arm/v6"))
        assert Platform.parse("linux/arm/v7").satisfied_by(Platform.parse("linux/arm/v7"))

    def test_a_different_architecture_never_matches(self):
        assert not Platform.parse("linux/amd64").satisfied_by(Platform.parse("linux/arm64"))

    def test_attestation_entries_are_not_platforms(self):
        entry = {"platform": {"os": "unknown", "architecture": "unknown"}}
        assert Platform.from_index_entry(entry) is None
        assert Platform.from_index_entry({}) is None
        assert Platform.from_index_entry({"platform": "amd64"}) is None

    def test_default_variants_follow_the_architecture(self):
        assert Platform.parse("linux/arm64").default_variant == "v8"
        assert Platform.parse("linux/arm").default_variant == "v7"
        assert Platform.parse("linux/amd64").default_variant == ""
