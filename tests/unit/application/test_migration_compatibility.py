"""Compatibility claims in a migration plan: only what was established.

`direct_replacement` may only be true when nothing known argues against it;
what nothing could settle is listed as unverified rather than assumed away.
"""

from __future__ import annotations

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.application.services.migration import plan_migration
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.image_facts import EvidenceSource, HardeningFacts
from dockerls.domain.entities.scan_result import ScanResult


def _image(
    tag: str,
    *,
    family: str = "alpine",
    user: str | None = None,
    entrypoint: list[str] | None = None,
    platform: str = "",
    name: str = "node",
) -> ImageAnalysis:
    evidence = {}
    facts = HardeningFacts()
    if user is not None:
        facts.user = user
        evidence["runs_as_non_root"] = EvidenceSource.REGISTRY
    if entrypoint is not None:
        facts.entrypoint = entrypoint
        evidence["entrypoint"] = EvidenceSource.REGISTRY
    facts.evidence = evidence
    return ImageAnalysis(
        image=DockerImage(name=name, tag=tag, platform=platform),
        scan=ScanResult(
            image_reference=f"{name}:{tag}",
            scan_timestamp="2026-01-01T00:00:00Z",
            os_family=family,
        ),
        security_score=80.0,
        tier="B",
        remediation_score=60,
        facts=facts,
    )


def _plan(current, target):
    return plan_migration(current, target)


class TestMajorVersions:
    def test_a_major_upgrade_is_not_a_direct_replacement(self):
        plan = _plan(_image("22-alpine"), _image("24-alpine"))
        assert plan.direct_replacement is False
        assert any("major version 22 -> 24" in r for r in plan.incompatibilities)
        assert any("major version upgrade" in t for t in plan.trade_offs)

    def test_a_downgrade_is_named_as_one(self):
        plan = _plan(_image("24-alpine"), _image("22-alpine"))
        assert any("downgrade" in t for t in plan.trade_offs)

    def test_a_tag_without_a_version_cannot_be_called_compatible(self):
        plan = _plan(_image("latest"), _image("22-alpine"))
        assert plan.direct_replacement is False
        assert any("names no version" in r for r in plan.incompatibilities)


class TestBaseDistribution:
    def test_libc_change_is_confirmed_and_blocking(self):
        plan = _plan(_image("22-alpine"), _image("22-bookworm-slim", family="debian"))
        assert plan.direct_replacement is False
        assert any("[confirmed]" in r and "C library" in r for r in plan.incompatibilities)
        assert any("package manager changes" in t for t in plan.trade_offs)

    def test_an_unidentified_distribution_is_unknown_not_compatible(self):
        plan = _plan(_image("22-alpine", family=""), _image("22-alpine"))
        assert plan.direct_replacement is False
        assert any(r.startswith("[unknown]") for r in plan.incompatibilities)
        assert any("could not be identified" in t for t in plan.trade_offs)


class TestSameSameIsTheOnlyDirectReplacement:
    def test_same_major_same_family_same_platform_publisher(self):
        plan = _plan(_image("22-alpine"), _image("22.4-alpine"))
        assert plan.direct_replacement is True
        assert plan.incompatibilities == []

    def test_even_then_the_open_questions_are_listed(self):
        plan = _plan(_image("22-alpine"), _image("22.4-alpine"))
        assert any("application starts" in q for q in plan.unverified_compatibility)
        assert any("native libraries" in q for q in plan.unverified_compatibility)

    def test_a_different_platform_blocks_it(self):
        plan = _plan(
            _image("22-alpine", platform="linux/amd64"),
            _image("22-alpine", platform="linux/arm64"),
        )
        assert plan.direct_replacement is False
        assert any("[confirmed] platform" in r for r in plan.incompatibilities)


class TestUserAndEntrypoint:
    def test_a_changed_user_is_a_trade_off_when_both_were_measured(self):
        plan = _plan(_image("22-alpine", user=""), _image("22-alpine", user="65532"))
        assert any("default user changes (root -> 65532)" in t for t in plan.trade_offs)

    def test_an_unmeasured_side_yields_a_question_not_a_claim(self):
        plan = _plan(_image("22-alpine", user=""), _image("22-alpine"))
        assert not any("default user changes" in t for t in plan.trade_offs)
        assert any(
            "default user (one side was not inspected)" in q for q in plan.unverified_compatibility
        )

    def test_a_changed_entrypoint_is_flagged(self):
        plan = _plan(
            _image("22-alpine", entrypoint=["docker-entrypoint.sh"]),
            _image("22-alpine", entrypoint=["/nodejs/bin/node"]),
        )
        assert any("entrypoint or default command differ" in t for t in plan.trade_offs)

    def test_an_unchanged_entrypoint_is_silent(self):
        plan = _plan(
            _image("22-alpine", entrypoint=["node"]), _image("22.4-alpine", entrypoint=["node"])
        )
        assert not any("entrypoint" in t for t in plan.trade_offs)

    def test_native_libraries_are_never_claimed_verified_across_bases(self):
        plan = _plan(_image("22-alpine"), _image("22-bookworm-slim", family="debian"))
        assert any("cannot confirm that the native libraries" in t for t in plan.trade_offs)
