"""Hostile input, and the requirement that DockerLs fail *safe* under it.

Every input in this file is something an attacker or a broken upstream could
realistically produce: a YAML bomb from a compromised catalogue mirror, a
registry answering with a path that escapes its own namespace, a tag crafted
to look like a scanner flag, a cache file edited between runs.

The assertion is almost always the same, and it is the point: the tool
produces *nothing* rather than something wrong. A refused document yields no
candidate, never a candidate with default values; a failed scan yields
UNVERIFIED, never zero vulnerabilities. Failing closed is the behaviour;
these tests are what keep it.
"""

from __future__ import annotations

import pytest

from dockerls.application.services.verdict import apply_facts, finalize_verdict
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.image_facts import HardeningFacts
from dockerls.domain.entities.scan_result import ScanErrorKind, ScanResult, ScanStatus
from dockerls.domain.value_objects.confidence import Confidence
from dockerls.integrations.dhi.definition import parse_definition
from dockerls.utils.rate_limit import CircuitBreaker, CircuitOpenError, RateLimiter
from dockerls.utils.safe_yaml import (
    MAX_DEPTH,
    MAX_DOCUMENT_BYTES,
    MAX_EXPANDED_NODES,
    UnsafeYAMLError,
    safe_load_yaml,
)
from dockerls.utils.validation import sanitize_image_name


class TestYamlBombs:
    def test_the_classic_billion_laughs_is_refused_quickly(self):
        """Nine levels of nine-fold aliasing: ~200 bytes, 387 million nodes.

        The timing assertion is part of the test. A guard that refuses the
        document only *after* expanding it has not prevented the attack, it
        has performed it -- so the refusal has to come from measuring the
        composed graph, and therefore has to be effectively instant.
        """
        import time

        bomb = "a: &a [x,x,x,x,x,x,x,x,x]\n"
        for letter, previous in zip("bcdefghi", "abcdefgh", strict=True):
            bomb += f"{letter}: &{letter} [{', '.join([f'*{previous}'] * 9)}]\n"

        start = time.monotonic()
        with pytest.raises(UnsafeYAMLError, match="alias-expansion bomb"):
            safe_load_yaml(bomb, origin="bomb.yaml")
        assert time.monotonic() - start < 1.0

    def test_a_shallow_alias_count_is_not_what_bounds_the_bomb(self):
        """Pins the reason the previous heuristic was insufficient.

        The bomb above uses about seventy aliases -- a number no per-document
        alias cap would sensibly reject. What makes it dangerous is the
        product of the nesting, which is what `MAX_EXPANDED_NODES` bounds.
        """
        bomb = "a: &a [x,x,x,x,x,x,x,x,x]\n"
        for letter, previous in zip("bcdefghi", "abcdefgh", strict=True):
            bomb += f"{letter}: &{letter} [{', '.join([f'*{previous}'] * 9)}]\n"
        assert bomb.count("*") < 100
        assert MAX_EXPANDED_NODES > 100

    def test_an_oversized_document_is_refused_before_parsing(self):
        with pytest.raises(UnsafeYAMLError, match="over the"):
            safe_load_yaml("a: " + "x" * (MAX_DOCUMENT_BYTES + 1))

    def test_deep_nesting_is_refused(self):
        document = "a:" + "".join(f"\n{' ' * (i + 1)}b:" for i in range(MAX_DEPTH + 10)) + " 1"
        with pytest.raises(UnsafeYAMLError):
            safe_load_yaml(document)

    def test_ordinary_anchors_and_aliases_still_work(self):
        """Anchors are a normal YAML feature; they are bounded, not banned."""
        legitimate = "\n".join(["base: &base {a: 1}", *[f"k{i}: *base" for i in range(10)]])
        assert safe_load_yaml(legitimate)["k0"] == {"a": 1}

    def test_python_object_tags_never_construct_anything(self):
        """`yaml.load` here would be remote code execution outright."""
        with pytest.raises(UnsafeYAMLError):
            safe_load_yaml("!!python/object/apply:os.system ['echo pwned']")

    def test_malformed_yaml_raises_rather_than_returning_an_empty_document(self):
        with pytest.raises(UnsafeYAMLError, match="malformed"):
            safe_load_yaml("key: [unclosed\n  - list")

    def test_a_refused_definition_yields_no_candidate_not_a_blank_one(self):
        """The distinction that matters: unreadable is not "clean"."""
        assert parse_definition(None) is None
        assert parse_definition("a string") is None
        assert parse_definition({"unrelated": "keys"}) is None


class TestHostileDefinitions:
    def test_a_definition_cannot_inject_unbounded_tags(self):
        declared = parse_definition(
            {"image": "dhi.io/node", "tags": [f"t{i}" for i in range(10_000)]}
        )
        assert declared is not None
        assert len(declared.tags) <= 64

    def test_a_definition_cannot_inject_unbounded_packages(self):
        declared = parse_definition(
            {
                "image": "dhi.io/node",
                "tags": ["1"],
                "contents": {"packages": [f"p{i}" for i in range(20_000)]},
            }
        )
        assert declared is not None
        assert declared.declared_package_count is not None
        assert declared.declared_package_count <= 5000

    def test_package_matching_is_exact_not_substring(self):
        """`libcurl4` is not `curl`; treating it as one invents a capability."""
        declared = parse_definition(
            {
                "image": "dhi.io/x",
                "tags": ["1"],
                "contents": {"packages": ["libcurl4", "bash-completion", "apt-utils"]},
            }
        )
        assert declared is not None
        assert declared.debug_tool_packages == ()
        assert declared.shell_packages == ()
        assert declared.package_manager_packages == ()

    def test_control_characters_in_declared_values_stay_data(self):
        """Terminal escapes must never become terminal *behaviour*.

        Rich renders values as text, so the guarantee here is that the
        parser neither interprets nor strips them silently -- the string
        arrives as the string it was, and the renderer escapes it.
        """
        declared = parse_definition(
            {"image": "dhi.io/x", "tags": ["1"], "variant": "\x1b[31mred\x1b[0m"}
        )
        assert declared is not None
        assert declared.variant == "\x1b[31mred\x1b[0m"


class TestMaliciousReferences:
    @pytest.mark.parametrize(
        "name",
        [
            "--ignore-unfixed",
            "-v/etc:/etc",
            "node/../../../etc/passwd",
            "node:22; rm -rf /",
            "node:22 && curl evil.example",
            "node$(id)",
            "node`id`",
            "node|cat",
            "node\nrm -rf /",
            "",
            " ",
        ],
    )
    def test_references_that_are_not_images_are_refused(self, name):
        with pytest.raises(ValueError):  # noqa: PT011 - message varies by cause
            sanitize_image_name(name)

    def test_an_over_long_reference_is_refused(self):
        with pytest.raises(ValueError, match="exceeds"):
            sanitize_image_name("a" * 300)

    @pytest.mark.parametrize(
        "name",
        [
            "node",
            "node:22-alpine",
            "library/node:22",
            "ghcr.io/org/app:1.2.3",
            "registry.internal:5000/team/app",
            "dhi.io/node:22-debian13",
            "node@sha256:" + "a" * 64,
        ],
    )
    def test_legitimate_references_still_pass(self, name):
        assert sanitize_image_name(name) == name


class TestFailureIsNeverSafety:
    @pytest.mark.parametrize(
        ("status", "kind"),
        [
            (ScanStatus.ERROR, ScanErrorKind.SCANNER_MISSING),
            (ScanStatus.ERROR, ScanErrorKind.DB_INIT_FAILED),
            (ScanStatus.TIMEOUT, ScanErrorKind.TIMEOUT),
            (ScanStatus.ERROR, ScanErrorKind.RATE_LIMITED),
            (ScanStatus.ERROR, ScanErrorKind.INVALID_OUTPUT),
            (ScanStatus.PARTIAL, ScanErrorKind.NONE),
        ],
    )
    def test_every_technical_failure_is_unverified_never_clean(self, status, kind):
        """Zero vulnerabilities and zero *measurements* must never be equal."""
        from dockerls.application.dto.analysis import ImageAnalysis

        analysis = ImageAnalysis(
            image=DockerImage(name="node", tag="22", digest="sha256:" + "a" * 64),
            scan=ScanResult(
                image_reference="node:22",
                status=status,
                error_kind=kind,
                scan_timestamp="2026-01-01T00:00:00Z",
                vulnerabilities=[],
            ),
            security_score=100.0,
            tier="A",
            remediation_score=100,
        )
        analysis.hub_tag_verified = True
        apply_facts(analysis, HardeningFacts())
        finalize_verdict(analysis, cross_validated=True)

        assert analysis.confidence is Confidence.UNVERIFIED
        assert analysis.confidence.is_recommendable is False
        assert any("nothing was measured" in reason for reason in analysis.confidence_reasons)

    def test_a_scan_with_no_timestamp_is_not_verified(self):
        scan = ScanResult(image_reference="node:22", status=ScanStatus.OK, scan_timestamp="")
        assert scan.is_verified is False


class TestRateLimitingAndBreakers:
    async def test_the_limiter_paces_a_burst(self):
        import time

        limiter = RateLimiter(rate=2, period=0.2, burst=2)
        start = time.monotonic()
        for _ in range(4):
            await limiter.acquire()
        assert time.monotonic() - start >= 0.15

    def test_the_limiter_refuses_nonsense_configuration(self):
        with pytest.raises(ValueError, match="rate"):
            RateLimiter(rate=0)
        with pytest.raises(ValueError, match="period"):
            RateLimiter(rate=1, period=0)

    def test_the_breaker_opens_after_repeated_failures(self):
        breaker = CircuitBreaker(threshold=3, cooldown=60.0)
        for _ in range(3):
            breaker.record_failure()
        assert breaker.is_open
        with pytest.raises(CircuitOpenError, match="unavailable"):
            breaker.check("GitHub API")

    def test_a_success_closes_the_breaker(self):
        breaker = CircuitBreaker(threshold=2, cooldown=60.0)
        breaker.record_failure()
        breaker.record_failure()
        assert breaker.is_open
        breaker.record_success()
        assert not breaker.is_open
        breaker.check("GitHub API")

    def test_the_breaker_stays_open_while_failures_continue(self):
        """A provider that keeps failing must not get a fresh window."""
        breaker = CircuitBreaker(threshold=1, cooldown=0.05)
        breaker.record_failure()
        opened_at = breaker._opened_at  # noqa: SLF001 - asserting the re-stamp
        breaker.record_failure()
        assert breaker._opened_at >= opened_at  # noqa: SLF001
        assert breaker.is_open
