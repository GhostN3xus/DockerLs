"""What changed since the previous run, and whether the image or the scanner's
database is to blame -- without ever inventing a cause."""

from __future__ import annotations

from typing import Any

from dockerls.application.services.run_diff import Cause, diff_runs

OLD_DIGEST = "sha256:" + "1" * 64
NEW_DIGEST = "sha256:" + "2" * 64


def _vuln(cve, package="openssl", version="3.0.1", severity="HIGH"):
    return {
        "cve_id": cve,
        "package_name": package,
        "installed_version": version,
        "severity": severity,
        "fixed_version": "",
    }


def _analysis(
    reference="node:22",
    digest=OLD_DIGEST,
    db="2026-09-01T00:00:00+00:00",
    vulns=(),
    scanner="trivy",
    version="0.60",
):
    return {
        "image": {"full_reference": reference, "digest": digest},
        "scan": {"vulnerabilities": list(vulns)},
        "provenance": {"db_revision": db, "scanner": scanner, "scanner_version": version},
    }


def _run(*analyses, run_id="20260901T000000Z-aaaaaaaa", **overrides) -> dict[str, Any]:
    document = {
        "run_id": run_id,
        "created_at": "2026-09-01T00:00:00+00:00",
        "command": "recommend",
        "query": "node",
        "platform": "linux/amd64",
        "filters": "",
        "result": {"recommendations": list(analyses)},
    }
    document.update(overrides)
    return document


def test_same_image_new_database_is_attributed_to_the_database():
    before = _run(_analysis(vulns=[_vuln("CVE-1")]))
    after = _run(
        _analysis(db="2026-09-02T00:00:00+00:00", vulns=[_vuln("CVE-1"), _vuln("CVE-2")]),
        run_id="20260902T000000Z-bbbbbbbb",
    )

    entry = diff_runs(before, after).images[0]

    assert entry.cause is Cause.SCANNER_DATABASE_CHANGED
    assert [f.cve_id for f in entry.new] == ["CVE-2"]
    assert entry.removed == []


def test_a_moved_tag_is_attributed_to_the_image():
    before = _run(_analysis(vulns=[_vuln("CVE-1")]))
    after = _run(_analysis(digest=NEW_DIGEST, vulns=[]))

    entry = diff_runs(before, after).images[0]

    assert entry.cause is Cause.IMAGE_CHANGED
    assert [f.cve_id for f in entry.removed] == ["CVE-1"]


def test_both_changing_is_reported_as_both_not_guessed_as_one():
    before = _run(_analysis(vulns=[_vuln("CVE-1")]))
    after = _run(
        _analysis(digest=NEW_DIGEST, db="2026-09-02T00:00:00+00:00", vulns=[_vuln("CVE-3")])
    )

    assert diff_runs(before, after).images[0].cause is Cause.IMAGE_AND_DATABASE_CHANGED


def test_a_difference_with_neither_changed_is_unexplained_and_says_so():
    before = _run(_analysis(vulns=[_vuln("CVE-1")]))
    after = _run(_analysis(vulns=[_vuln("CVE-9")]))

    entry = diff_runs(before, after).images[0]

    assert entry.cause is Cause.UNEXPLAINED
    assert "not attributed" in entry.note


def test_no_difference_is_no_change():
    run = _run(_analysis(vulns=[_vuln("CVE-1")]))
    assert diff_runs(run, run).images[0].cause is Cause.NO_CHANGE


def test_an_unknown_database_revision_is_never_read_as_unchanged():
    before = _run(_analysis(db="", vulns=[_vuln("CVE-1")]))
    after = _run(_analysis(db="", vulns=[_vuln("CVE-1"), _vuln("CVE-2")]))

    entry = diff_runs(before, after).images[0]

    assert entry.cause is Cause.UNEXPLAINED
    assert "revision" in entry.note and "unknown" in entry.note


def test_finding_identity_includes_the_installed_version():
    """The same CVE in an upgraded-but-still-vulnerable package is a new finding
    and a removed one -- not 'no change'."""
    before = _run(_analysis(vulns=[_vuln("CVE-1", version="3.0.1")]))
    after = _run(_analysis(vulns=[_vuln("CVE-1", version="3.0.2")]))

    entry = diff_runs(before, after).images[0]

    assert [f.installed_version for f in entry.new] == ["3.0.2"]
    assert [f.installed_version for f in entry.removed] == ["3.0.1"]


def test_the_package_is_part_of_the_identity_too():
    before = _run(_analysis(vulns=[_vuln("CVE-1", package="libssl")]))
    after = _run(_analysis(vulns=[_vuln("CVE-1", package="libcrypto")]))

    entry = diff_runs(before, after).images[0]

    assert len(entry.new) == len(entry.removed) == 1


class TestOnlyCompatibleScopesAreCompared:
    def test_a_different_platform_is_not_compared(self):
        before = _run(_analysis(), platform="linux/arm64")
        diff = diff_runs(before, _run(_analysis()))

        assert diff.compatible is False and diff.images == []
        assert "platform" in diff.note

    def test_different_filters_are_not_compared(self):
        assert (
            diff_runs(_run(_analysis(), filters="distro=alpine"), _run(_analysis())).compatible
            is False
        )

    def test_a_different_question_is_not_compared(self):
        assert diff_runs(_run(_analysis(), query="python"), _run(_analysis())).compatible is False

    def test_different_scanners_are_not_compared(self):
        before = _run(_analysis(scanner="trivy"))
        after = _run(_analysis(scanner="grype"))

        entry = diff_runs(before, after).images[0]

        assert entry.cause is Cause.NOT_COMPARABLE
        assert "different scanners" in entry.note

    def test_an_unknown_digest_cannot_be_judged(self):
        entry = diff_runs(_run(_analysis(digest="")), _run(_analysis())).images[0]
        assert entry.cause is Cause.NOT_COMPARABLE

    def test_an_image_only_one_run_measured_is_simply_absent(self):
        diff = diff_runs(_run(_analysis(reference="node:20")), _run(_analysis(reference="node:22")))
        assert diff.images == [] and "no image appears in both" in diff.note


def test_an_analyze_run_document_is_understood():
    single = {
        "result": _analysis(vulns=[_vuln("CVE-1")]),
        "command": "analyze",
        "query": "node:22",
        "platform": "linux/amd64",
        "filters": "",
        "run_id": "20260901T000000Z-aaaaaaaa",
    }
    newer = {**single, "result": _analysis(vulns=[])}

    assert diff_runs(single, newer).images[0].removed[0].cve_id == "CVE-1"
