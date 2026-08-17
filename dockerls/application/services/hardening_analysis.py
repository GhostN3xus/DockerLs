"""Assemble one evidence record per image from every source that can speak.

Three sources can say something about how an image is built, and they are
not equal:

* the **registry** serves the OCI config of a resolved digest -- a
  measurement of the published artifact;
* the **scanner** reports the packages it found -- also a measurement, and
  the only one that can see inside the filesystem;
* the **catalogue** publishes the vendor's build definition -- a claim about
  intent.

They are merged in that order, and the precedence is absolute: a measurement
is never overwritten by a claim. Where a claim contradicts a measurement,
the contradiction is *recorded* rather than resolved, because a vendor
saying an image runs unprivileged while its config says root is a finding in
its own right -- arguably the most useful thing this whole comparison
produces.

The asymmetry from `DeclaredImageMetadata` carries through here: presence of
a shell package proves a shell, absence proves nothing. Every fact this
service cannot establish stays UNKNOWN, and UNKNOWN earns no credit in any
score downstream.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from loguru import logger

from dockerls.domain.entities.declared_metadata import (
    DEBUG_TOOL_PACKAGES,
    PACKAGE_MANAGER_PACKAGES,
    SHELL_PACKAGES,
)
from dockerls.domain.entities.image_facts import EvidenceSource, HardeningFacts
from dockerls.domain.value_objects.tristate import Tristate

if TYPE_CHECKING:
    from dockerls.domain.entities.image import DockerImage
    from dockerls.domain.entities.scan_result import ScanResult
    from dockerls.integrations.registry.inspector import RegistryInspector


class HardeningAnalyzer:
    """Produces the digest and merged facts for one candidate."""

    def __init__(self, inspector: RegistryInspector | None = None):
        self._inspector = inspector

    async def resolve_digest(self, image: DockerImage) -> str:
        """The image's manifest digest, or "" when it cannot be resolved.

        Exposed separately from `analyze` because deduplication needs the
        digest for *every* candidate, while the full evidence gathering is
        only worth doing for the finalists.
        """
        if self._inspector is None:
            return ""
        try:
            return await self._inspector.resolve_digest(image)
        except Exception as e:
            logger.warning(f"Could not resolve a digest for {image.full_reference}: {e}")
            return ""

    async def close(self) -> None:
        """Release the registry connection pools this analyzer opened."""
        if self._inspector is not None:
            await self._inspector.close()

    async def analyze(
        self, image: DockerImage, scan: ScanResult | None
    ) -> tuple[str, HardeningFacts]:
        """Return (resolved digest, merged facts).

        The digest is "" when the registry could not be reached; the caller
        keeps whatever digest it already had rather than clearing it.
        """
        digest, facts = "", HardeningFacts()
        if self._inspector is not None:
            try:
                digest, facts = await self._inspector.inspect(image)
            except Exception as e:
                # Inspection is enrichment. A registry that will not answer
                # must cost the candidate its *facts*, never its analysis.
                logger.warning(f"Could not inspect {image.full_reference}: {e}")

        if scan is not None:
            facts = _merge_scanner_evidence(facts, scan)
        if image.declared is not None:
            facts = _merge_declared(facts, image)
        return digest, facts


def _merge_scanner_evidence(facts: HardeningFacts, scan: ScanResult) -> HardeningFacts:
    """Fold in what the scanner saw inside the filesystem.

    The scanner reports packages that carry vulnerabilities, not the full
    inventory, so this can only ever establish *presence*: seeing `bash`
    among the findings proves a shell is installed, while not seeing it
    proves nothing at all and leaves the fact UNKNOWN. The package count is
    deliberately not derived from this -- the number of vulnerable packages
    is not the number of packages, and reporting it as one would be a
    fabricated measurement.
    """
    names = {v.package_name.strip().lower() for v in scan.vulnerabilities if v.package_name}
    if not names:
        return facts

    updates: dict[str, object] = {}
    evidence = dict(facts.evidence)
    for fact, known in (
        ("has_shell", SHELL_PACKAGES),
        ("has_package_manager", PACKAGE_MANAGER_PACKAGES),
        ("has_debug_tools", DEBUG_TOOL_PACKAGES),
    ):
        if names & known and not getattr(facts, fact).is_true:
            updates[fact] = Tristate.TRUE
            evidence[fact] = EvidenceSource.SCANNER

    if not updates:
        return facts
    updates["evidence"] = evidence
    return facts.model_copy(update=updates)


def _merge_declared(facts: HardeningFacts, image: DockerImage) -> HardeningFacts:
    """Fill remaining gaps from the catalogue, and record contradictions.

    Only facts still UNKNOWN are filled. Anything the registry or the
    scanner determined stands, and a declaration that disagrees with it is
    appended to `conflicts` instead of being applied.
    """
    declared = image.declared
    if declared is None:
        return facts

    updates: dict[str, object] = {}
    evidence = dict(facts.evidence)
    conflicts = list(facts.conflicts)

    claims = (
        ("runs_as_non_root", declared.declared_non_root, "runs as a non-root account"),
        ("has_shell", declared.declared_has_shell, "ships a shell"),
        ("has_package_manager", declared.declared_has_package_manager, "ships a package manager"),
        ("has_debug_tools", declared.declared_has_debug_tools, "ships debug tooling"),
    )
    for fact, claim, description in claims:
        if not claim.is_known:
            continue
        current: Tristate = getattr(facts, fact)
        if not current.is_known:
            updates[fact] = claim
            evidence[fact] = EvidenceSource.CATALOG
        elif current is not claim:
            conflicts.append(
                f"{declared.catalog or 'the catalogue'} declares this image "
                f"{'' if claim.is_true else 'does not '}{description}, but the "
                f"{facts.source_of(fact).value} evidence says otherwise"
            )

    if facts.package_count is None and declared.declared_package_count is not None:
        updates["package_count"] = declared.declared_package_count
        evidence["package_count"] = EvidenceSource.CATALOG

    if not facts.os_family and declared.os_id:
        updates["os_family"] = declared.os_id

    if not updates and conflicts == facts.conflicts:
        return facts
    updates["evidence"] = evidence
    updates["conflicts"] = conflicts
    return facts.model_copy(update=updates)
