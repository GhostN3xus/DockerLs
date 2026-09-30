"""What changed since the previous run -- and *why*, when that can be known.

Two runs of `recommend node` a day apart can report different findings for
`node:22-alpine`, and the useful question is what moved: **the image** (the tag
now points at other bytes), **the scanner's database** (same bytes, but the
database learned about new CVEs), both, or neither -- in which case the
difference is unexplained and is reported as such instead of being assigned to
a plausible cause.

Only compatible scopes are compared. Two runs are compared when they asked
the same question of the same platform under the same filters, and an image is
compared only with *itself* (same reference), measured by the same scanner.
Findings are matched on their **full identity** -- CVE, package *and* installed
version -- so "the same CVE in a package that was upgraded but is still
vulnerable" shows up as a removed finding and a new one, not as no change.

Pure: it works on two saved run documents.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from dockerls.infrastructure.run_store import scope_of


class Cause(StrEnum):
    IMAGE_CHANGED = "IMAGE_CHANGED"
    SCANNER_DATABASE_CHANGED = "SCANNER_DATABASE_CHANGED"
    IMAGE_AND_DATABASE_CHANGED = "IMAGE_AND_DATABASE_CHANGED"
    UNEXPLAINED = "UNEXPLAINED"
    NO_CHANGE = "NO_CHANGE"
    NOT_COMPARABLE = "NOT_COMPARABLE"


class Finding(BaseModel):
    cve_id: str
    package: str
    installed_version: str = ""
    severity: str = ""
    fixed_version: str = ""


class ImageDiff(BaseModel):
    reference: str
    cause: Cause
    note: str = ""
    previous_digest: str = ""
    current_digest: str = ""
    previous_db_revision: str = ""
    current_db_revision: str = ""
    new: list[Finding] = Field(default_factory=list)
    removed: list[Finding] = Field(default_factory=list)


class RunDiff(BaseModel):
    schema_id: str = "dockerls.run-diff/1"
    previous_run_id: str = ""
    previous_created_at: str = ""
    compatible: bool = True
    note: str = ""
    images: list[ImageDiff] = Field(default_factory=list)


def _analyses(document: dict[str, Any]) -> list[dict[str, Any]]:
    result = document.get("result")
    if not isinstance(result, dict):
        return []
    if "scan" in result:  # an `analyze` run stores one analysis
        return [result]
    items: list[dict[str, Any]] = []
    for key in ("recommendations", "alternatives"):
        listed = result.get(key)
        if isinstance(listed, list):
            items.extend(a for a in listed if isinstance(a, dict))
    return items


def _findings(analysis: dict[str, Any]) -> dict[str, Finding]:
    scan = analysis.get("scan")
    vulns = scan.get("vulnerabilities") if isinstance(scan, dict) else None
    found: dict[str, Finding] = {}
    for v in vulns if isinstance(vulns, list) else []:
        if not isinstance(v, dict):
            continue
        finding = Finding(
            cve_id=str(v.get("cve_id") or "").strip().upper(),
            package=str(v.get("package_name") or "").strip().lower(),
            installed_version=str(v.get("installed_version") or "").strip(),
            severity=str(v.get("severity") or ""),
            fixed_version=str(v.get("fixed_version") or ""),
        )
        # Full identity: the version is part of it on purpose.
        found[f"{finding.cve_id}|{finding.package}|{finding.installed_version}"] = finding
    return found


def _reference(analysis: dict[str, Any]) -> str:
    image = analysis.get("image")
    return str(image.get("full_reference") or "") if isinstance(image, dict) else ""


def _digest(analysis: dict[str, Any]) -> str:
    image = analysis.get("image")
    return str(image.get("digest") or "") if isinstance(image, dict) else ""


def _provenance(analysis: dict[str, Any]) -> tuple[str, str, str]:
    prov = analysis.get("provenance")
    prov = prov if isinstance(prov, dict) else {}
    return (
        str(prov.get("db_revision") or ""),
        str(prov.get("scanner") or ""),
        str(prov.get("scanner_version") or ""),
    )


def _cause(image_changed: bool, db_changed: bool, any_difference: bool) -> Cause:
    if image_changed and db_changed:
        return Cause.IMAGE_AND_DATABASE_CHANGED
    if image_changed:
        return Cause.IMAGE_CHANGED
    if db_changed:
        return Cause.SCANNER_DATABASE_CHANGED
    return Cause.UNEXPLAINED if any_difference else Cause.NO_CHANGE


def diff_runs(previous: dict[str, Any], current: dict[str, Any]) -> RunDiff:
    """Compare two saved run documents; see the module docstring for the rules."""
    diff = RunDiff(
        previous_run_id=str(previous.get("run_id", "")),
        previous_created_at=str(previous.get("created_at", "")),
    )
    if scope_of(previous) != scope_of(current):
        diff.compatible = False
        diff.note = (
            "the previous run asked a different question (command, image, platform or "
            "filters differ), so nothing was compared"
        )
        return diff

    before = {_reference(a): a for a in _analyses(previous) if _reference(a)}
    for analysis in _analyses(current):
        reference = _reference(analysis)
        old = before.get(reference)
        if old is None:
            continue
        old_db, old_scanner, old_version = _provenance(old)
        new_db, new_scanner, new_version = _provenance(analysis)
        entry = ImageDiff(
            reference=reference,
            cause=Cause.NOT_COMPARABLE,
            previous_digest=_digest(old),
            current_digest=_digest(analysis),
            previous_db_revision=old_db,
            current_db_revision=new_db,
        )
        if old_scanner != new_scanner:
            entry.note = (
                f"different scanners ({old_scanner or 'unknown'} vs {new_scanner or 'unknown'})"
            )
            diff.images.append(entry)
            continue
        if not entry.previous_digest or not entry.current_digest:
            entry.note = "the digest of one side is unknown, so image change cannot be judged"
            diff.images.append(entry)
            continue

        image_changed = entry.previous_digest != entry.current_digest
        # An unknown revision on either side means the database cannot be
        # said to be the same: it is treated as *changed or unknown*, and the
        # note says which, rather than being read as "unchanged".
        db_unknown = not old_db or not new_db
        db_changed = db_unknown or old_db != new_db or old_version != new_version

        before_findings, after_findings = _findings(old), _findings(analysis)
        entry.new = [f for k, f in after_findings.items() if k not in before_findings]
        entry.removed = [f for k, f in before_findings.items() if k not in after_findings]
        entry.cause = _cause(
            image_changed, db_changed and not db_unknown, bool(entry.new or entry.removed)
        )
        if db_unknown and not image_changed:
            entry.note = (
                "the database revision of at least one run is unknown: the difference "
                "cannot be attributed to the image or to the database"
            )
            if entry.new or entry.removed:
                entry.cause = Cause.UNEXPLAINED
        elif entry.cause is Cause.UNEXPLAINED:
            entry.note = (
                "same image and same database revision, yet the findings differ: "
                "not attributed to either"
            )
        diff.images.append(entry)

    if not diff.images:
        diff.note = "no image appears in both runs, so nothing was compared"
    return diff
