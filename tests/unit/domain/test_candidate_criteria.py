"""Compatibility filters: what is excluded before a scan is spent, and how sure we are.

The line the result must never blur is CONFIRMED (published data or a
measurement) versus HEURISTIC (a tag's name). A tag that simply does not say is
kept -- excluding it would be guessing in the direction that hides options.
"""

from __future__ import annotations

import pytest

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.value_objects.candidate_criteria import (
    Basis,
    CandidateCriteria,
    InvalidCriteriaError,
    VersionRange,
    apply_criteria,
    family_of_tag,
    variant_of_tag,
)


def _image(tag: str, name: str = "node", **kwargs) -> DockerImage:
    return DockerImage(name=name, tag=tag, **kwargs)


class TestVersionRanges:
    @pytest.mark.parametrize(
        ("spec", "accepted", "rejected"),
        [
            ("22", [(22,), (22, 5), (22, 5, 1)], [(20,), (23,), (2, 2)]),
            ("22.5", [(22, 5), (22, 5, 9)], [(22, 4), (22, 6), (22,)]),
            ("22.x", [(22, 1)], [(21, 9)]),
            (">=20,<23", [(20,), (22, 9), (22, 99, 1)], [(19, 9), (23,), (23, 0)]),
            ("20-22", [(20,), (21, 3), (22, 14)], [(19,), (23,)]),
            (">20", [(20, 1), (21,)], [(20,), (19,)]),
            ("<=18", [(18,), (16, 4)], [(18, 1), (19,)]),
        ],
    )
    def test_ranges_accept_and_reject_what_they_say(self, spec, accepted, rejected):
        rng = VersionRange.parse(spec)
        for version in accepted:
            assert rng.accepts(version), f"{spec} should accept {version}"
        for version in rejected:
            assert not rng.accepts(version), f"{spec} should reject {version}"

    @pytest.mark.parametrize("spec", ["", "latest", "22-alpine", ">=x", "20-", "23-20", "1,2"])
    def test_garbage_is_refused_not_guessed_at(self, spec):
        with pytest.raises(InvalidCriteriaError):
            VersionRange.parse(spec)


class TestTagReading:
    @pytest.mark.parametrize(
        ("tag", "family"),
        [
            ("22-alpine", "alpine"),
            ("22-bookworm-slim", "debian"),
            ("22-slim", "debian"),
            ("noble", "ubuntu"),
            ("22", ""),
            ("latest", ""),
            ("lts", ""),
        ],
    )
    def test_a_family_is_named_only_when_the_tag_names_one(self, tag, family):
        assert family_of_tag(_image(tag)) == family

    @pytest.mark.parametrize(
        ("tag", "expected"),
        [("22", "runtime"), ("22-alpine", "runtime"), ("latest-dev", "dev"), ("debug", "dev")],
    )
    def test_variants(self, tag, expected):
        assert variant_of_tag(_image(tag)).value == expected

    def test_the_repository_name_counts_too(self):
        assert family_of_tag(_image("latest", name="cgr.dev/chainguard/node")) == "wolfi"


class TestExclusion:
    def test_a_confirmed_platform_mismatch_is_excluded_and_marked_confirmed(self):
        criteria = CandidateCriteria.build(platform="linux/arm64")
        amd64_only = _image("22", available_architectures=["amd64"])

        exclusion = criteria.evaluate(amd64_only)

        assert exclusion is not None
        assert exclusion.criterion == "platform"
        assert exclusion.basis is Basis.CONFIRMED

    def test_a_listing_that_does_not_say_which_platforms_is_kept(self):
        criteria = CandidateCriteria.build(platform="linux/arm64")
        assert criteria.evaluate(_image("22")) is None

    def test_a_listing_that_offers_the_platform_is_kept(self):
        criteria = CandidateCriteria.build(platform="linux/arm64")
        assert criteria.evaluate(_image("22", available_architectures=["amd64", "arm64"])) is None

    def test_a_runtime_outside_the_range_is_a_heuristic_exclusion(self):
        exclusion = CandidateCriteria.build(runtime_version=">=20,<23").evaluate(
            _image("24-alpine")
        )
        assert exclusion is not None
        assert (exclusion.criterion, exclusion.basis) == ("runtime", Basis.HEURISTIC)

    def test_a_tag_with_no_version_is_kept_by_a_runtime_filter(self):
        assert CandidateCriteria.build(runtime_version="22").evaluate(_image("lts")) is None

    def test_a_named_other_distribution_is_excluded_heuristically(self):
        exclusion = CandidateCriteria.build(distro="alpine").evaluate(_image("22-bookworm"))
        assert exclusion is not None
        assert (exclusion.criterion, exclusion.basis) == ("distro", Basis.HEURISTIC)

    def test_an_unmarked_tag_is_kept_by_a_distribution_filter(self):
        assert CandidateCriteria.build(distro="alpine").evaluate(_image("22")) is None

    def test_a_dev_image_is_excluded_when_runtime_is_asked_for(self):
        exclusion = CandidateCriteria.build(variant="runtime").evaluate(_image("22-dev"))
        assert exclusion is not None and exclusion.criterion == "variant"

    def test_no_criteria_excludes_nothing(self):
        images = [_image("22"), _image("20-alpine")]
        outcome = apply_criteria(images, CandidateCriteria())
        assert outcome.kept == images and outcome.excluded == []

    def test_every_exclusion_names_its_reason_and_reference(self):
        outcome = apply_criteria(
            [_image("22-alpine"), _image("22-bookworm"), _image("18-alpine")],
            CandidateCriteria.build(distro="alpine", runtime_version="22"),
        )
        assert [i.tag for i in outcome.kept] == ["22-alpine"]
        assert {e.reference for e in outcome.excluded} == {"node:22-bookworm", "node:18-alpine"}
        assert all(e.reason for e in outcome.excluded)


class TestConfirmationAfterTheScan:
    def test_the_scanners_reading_of_the_image_overrules_the_tag_name(self):
        criteria = CandidateCriteria.build(distro="alpine")
        mislabelled = _image("22-alpine")  # the tag says alpine ...

        verdict = criteria.confirm(mislabelled, os_family="debian")  # ... the scanner says debian

        assert verdict is not None
        assert verdict.basis is Basis.CONFIRMED
        assert "debian" in verdict.reason

    def test_a_match_is_kept(self):
        assert CandidateCriteria.build(distro="alpine").confirm(_image("22"), "alpine") is None

    def test_wolfi_and_chainguard_are_one_family(self):
        assert CandidateCriteria.build(distro="chainguard").confirm(_image("x"), "wolfi") is None

    def test_an_unmeasured_family_is_neither_kept_nor_excluded_by_confirmation(self):
        assert CandidateCriteria.build(distro="alpine").confirm(_image("22"), "") is None


class TestWhenTheFiltersEliminateEverything:
    def test_the_explanation_names_counts_and_how_each_was_decided(self):
        criteria = CandidateCriteria.build(distro="alpine", variant="dev")
        images = [_image("22-bookworm"), _image("20-slim"), _image("22-alpine")]
        outcome = apply_criteria(images, criteria)

        text = outcome.explain_empty(criteria, discovered=3)

        assert "No candidate matches" in text
        assert "distro=alpine" in text and "variant=dev" in text
        assert "3 of 3" in text
        assert "tag names" in text, "the reader is told these rest on names, not measurements"


class TestBuildValidation:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"distro": "slackware"},
            {"variant": "production"},
            {"runtime_version": "abc"},
            {"platform": "linux"},
        ],
    )
    def test_bad_values_are_refused(self, kwargs):
        with pytest.raises(ValueError):
            CandidateCriteria.build(**kwargs)

    def test_describe_lists_only_what_is_active(self):
        assert CandidateCriteria().describe() == "none"
        assert (
            CandidateCriteria.build(platform="linux/arm64", distro="alpine").describe()
            == "platform=linux/arm64, distro=alpine"
        )
