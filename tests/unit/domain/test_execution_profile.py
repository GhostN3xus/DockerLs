"""Profiles: named bundles that never turn a skipped check into a passed one."""

from __future__ import annotations

import pytest

from dockerls.domain.value_objects.execution_profile import (
    PROFILES,
    Enrichment,
    ProfileName,
    UnknownProfileError,
    resolve_profile,
)
from dockerls.domain.value_objects.scan_plan import DEFAULT_SCAN_BUDGET


def test_no_profile_means_no_profile():
    assert resolve_profile(None) is None
    assert resolve_profile("  ") is None


def test_names_are_case_insensitive():
    assert resolve_profile("QUICK") is PROFILES[ProfileName.QUICK]


def test_an_unknown_profile_names_the_choices():
    with pytest.raises(UnknownProfileError, match="quick, standard, audit"):
        resolve_profile("thorough")


def test_standard_spells_out_todays_defaults():
    standard = PROFILES[ProfileName.STANDARD]
    assert standard.scan_budget == DEFAULT_SCAN_BUDGET
    assert standard.cross_validate and standard.verify_tags and standard.inspect_finalists
    assert standard.enrichment is Enrichment.ALL
    assert standard.not_performed() == []


def test_quick_measures_less_and_says_what_it_does_not_check():
    quick, standard = PROFILES[ProfileName.QUICK], PROFILES[ProfileName.STANDARD]
    assert 0 < quick.scan_budget < standard.scan_budget
    assert not quick.cross_validate
    skipped = quick.not_performed()
    assert any("cross-validation" in item for item in skipped)
    assert any("threat intelligence" in item for item in skipped)
    assert all(
        "not run in this profile" in item or "outside the finalists" in item for item in skipped
    )


def test_audit_covers_everything_and_skips_nothing():
    audit = PROFILES[ProfileName.AUDIT]
    assert audit.scan_budget == 0, "0 measures every discovered tag"
    assert audit.cross_validate and audit.verify_tags and audit.inspect_finalists
    assert audit.enrichment is Enrichment.ALL
    assert audit.not_performed() == []


def test_every_profile_states_its_purpose():
    assert all(profile.summary for profile in PROFILES.values())
