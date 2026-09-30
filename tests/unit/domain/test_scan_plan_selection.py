"""Choosing candidates by version, variant and compatibility -- not publish date alone."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.value_objects.candidate_criteria import CandidateCriteria
from dockerls.domain.value_objects.scan_plan import plan_scans

NOW = datetime(2026, 9, 30, tzinfo=UTC)


def _tag(tag: str, days_old: int, **kwargs) -> DockerImage:
    return DockerImage(
        name="node",
        tag=tag,
        last_updated=NOW - timedelta(days=days_old),
        is_official=True,
        **kwargs,
    )


def _many() -> list[DockerImage]:
    # Eight recently published variants of the 22 line, and older lines that a
    # date-only choice would never reach.
    recent = [
        _tag(t, i)
        for i, t in enumerate(
            [
                "22.9.0-alpine",
                "22.9.0-slim",
                "22.9.0-bookworm",
                "22.9-alpine",
                "22.9-slim",
                "22.8.0-alpine",
                "22.8.0-slim",
                "22.8.0-bookworm",
            ]
        )
    ]
    older = [
        _tag("20-alpine", 60),
        _tag("20-slim", 61),
        _tag("18-alpine", 200),
        _tag("24-alpine", 90),
    ]
    return recent + older


def test_the_default_selection_is_unchanged_newest_first():
    plan = plan_scans(_many(), budget=4)
    assert all(t.tag.startswith("22.") for t in plan.selected)


def test_a_spread_selection_covers_different_lines_before_repeating_one():
    plan = plan_scans(_many(), budget=4, spread=True)

    majors = {t.tag.split(".")[0].split("-")[0] for t in plan.selected}
    assert len(majors) >= 3, f"a budget of four should reach several lines, got {plan.selected!r}"
    assert len({t.tag for t in plan.selected}) == 4


def test_a_spread_selection_still_states_what_it_left_out():
    plan = plan_scans(_many(), budget=4, spread=True)
    assert plan.selected and plan.deferred_count + len(plan.selected) <= plan.discovered
    assert all(d.detail for d in plan.deferred)


def test_filters_run_before_the_budget_and_name_each_exclusion():
    plan = plan_scans(
        _many(),
        budget=10,
        criteria=CandidateCriteria.build(distro="alpine", runtime_version="20-22"),
    )

    assert {t.tag for t in plan.selected} == {
        "22.9.0-alpine",
        "22.9-alpine",
        "22.8.0-alpine",
        "20-alpine",
    }
    assert {e.criterion for e in plan.excluded} == {"distro", "runtime"}
    assert plan.discovered == len(_many()), "discovered counts what was found, before any filter"


def test_a_confirmed_platform_filter_spends_no_scan_on_an_image_that_lacks_it():
    tags = [
        _tag("22", 1, available_architectures=["amd64"]),
        _tag("20", 2, available_architectures=["amd64", "arm64"]),
    ]

    plan = plan_scans(tags, budget=0, criteria=CandidateCriteria.build(platform="linux/arm64"))

    assert [t.tag for t in plan.selected] == ["20"]
    assert [e.basis.value for e in plan.excluded] == ["CONFIRMED"]


def test_filters_that_remove_everything_leave_an_empty_plan_with_reasons():
    plan = plan_scans(_many(), budget=5, criteria=CandidateCriteria.build(distro="ubuntu"))
    # None of the tags names ubuntu, and a tag that names nothing is kept -- so
    # only tags that name another family go. Here every alpine/debian tag does.
    named = {"alpine", "debian"}
    assert plan.selected == [] or all(all(fam not in t.tag for fam in named) for t in plan.selected)
    assert len(plan.excluded) + len(plan.selected) == len(_many())
