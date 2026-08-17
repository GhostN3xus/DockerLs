"""Source selection, evidence merging, and migration honesty.

Three separate concerns share a file because they share one property: each
of them is a place where it would be easy, and wrong, to state something
nobody established -- that a source exists, that a vendor's claim is a
measurement, or that a migration is compatible.
"""

from __future__ import annotations

import pytest

from dockerls.application.dto.analysis import DimensionReport, ImageAnalysis
from dockerls.application.services.hardening_analysis import HardeningAnalyzer
from dockerls.application.services.migration import plan_migration
from dockerls.application.services.source_registry import (
    ALL_SOURCES,
    SourceRegistry,
    SourceSpec,
    UnknownSourceError,
)
from dockerls.domain.entities.declared_metadata import DeclaredImageMetadata
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.image_facts import EvidenceSource, HardeningFacts
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.value_objects.confidence import Confidence
from dockerls.domain.value_objects.tristate import Tristate


def _registry(**flags) -> SourceRegistry:
    registry = SourceRegistry()
    registry.register(SourceSpec(name="dockerhub", label="Docker Hub", build=_noop, primary=True))
    registry.register(
        SourceSpec(
            name="chainguard",
            label="Chainguard",
            build=_noop,
            default_enabled=flags.get("chainguard", True),
        )
    )
    registry.register(
        SourceSpec(
            name="dhi",
            label="Docker Hardened Images",
            build=_noop,
            default_enabled=flags.get("dhi", False),
            requires_auth=True,
        )
    )
    return registry


async def _noop():  # pragma: no cover - never awaited in these tests
    raise AssertionError("builder should not run")


class TestSourceRegistry:
    def test_the_default_selection_excludes_opt_in_sources(self):
        names = [spec.name for spec in _registry().resolve()]
        assert names == ["dockerhub", "chainguard"]

    def test_all_sources_includes_the_opt_in_ones(self):
        names = [spec.name for spec in _registry().resolve(all_sources=True)]
        assert names == ["dockerhub", "chainguard", "dhi"]

    def test_the_all_token_is_equivalent_to_the_flag(self):
        registry = _registry()
        assert registry.resolve([ALL_SOURCES]) == registry.resolve(all_sources=True)

    def test_an_explicit_selection_overrides_default_enabled(self):
        """Naming a source is a stronger statement than any default."""
        names = [spec.name for spec in _registry().resolve(["dhi"])]
        assert names == ["dhi"]

    def test_the_primary_source_is_always_first(self):
        names = [spec.name for spec in _registry().resolve(["chainguard", "dockerhub"])]
        assert names == ["dockerhub", "chainguard"]

    def test_include_optional_false_keeps_only_the_primary(self):
        names = [spec.name for spec in _registry().resolve(include_optional=False)]
        assert names == ["dockerhub"]

    def test_an_unknown_source_names_the_valid_ones(self):
        with pytest.raises(UnknownSourceError) as exc:
            _registry().resolve(["dockerhubb"])
        assert "dockerhubb" in str(exc.value)
        assert "chainguard" in str(exc.value)
        assert ALL_SOURCES in str(exc.value)

    def test_selection_is_case_and_whitespace_insensitive(self):
        names = [spec.name for spec in _registry().resolve([" DHI "])]
        assert names == ["dhi"]

    def test_a_source_cannot_be_registered_twice(self):
        registry = _registry()
        with pytest.raises(ValueError, match="already registered"):
            registry.register(SourceSpec(name="dhi", label="x", build=_noop))

    def test_the_all_token_is_reserved(self):
        with pytest.raises(ValueError, match="reserved"):
            SourceRegistry().register(SourceSpec(name=ALL_SOURCES, label="x", build=_noop))


class TestEvidenceMerging:
    async def test_a_measurement_is_never_overwritten_by_a_claim(self):
        """The vendor says non-root; the config says root. The config wins."""
        image = DockerImage(
            name="dhi.io/node",
            tag="22",
            declared=DeclaredImageMetadata(catalog="DHI", run_as_user="node"),
        )
        measured = HardeningFacts(
            runs_as_non_root=Tristate.FALSE,
            config_verified=True,
            evidence={"runs_as_non_root": EvidenceSource.REGISTRY},
        )
        analyzer = HardeningAnalyzer(inspector=_StubInspector(measured))
        _, facts = await analyzer.analyze(image, None)

        assert facts.runs_as_non_root is Tristate.FALSE
        assert facts.source_of("runs_as_non_root") is EvidenceSource.REGISTRY
        assert facts.conflicts
        assert "DHI declares" in facts.conflicts[0]

    async def test_a_claim_fills_a_gap_and_is_labelled_as_a_claim(self):
        image = DockerImage(
            name="dhi.io/node",
            tag="22",
            declared=DeclaredImageMetadata(catalog="DHI", run_as_user="node"),
        )
        analyzer = HardeningAnalyzer(inspector=_StubInspector(HardeningFacts()))
        _, facts = await analyzer.analyze(image, None)

        assert facts.runs_as_non_root is Tristate.TRUE
        assert facts.source_of("runs_as_non_root") is EvidenceSource.CATALOG
        assert facts.is_verified("runs_as_non_root") is False
        assert facts.conflicts == []

    async def test_scanner_findings_prove_presence_only(self):
        scan = ScanResult(
            image_reference="node:22",
            status=ScanStatus.OK,
            scan_timestamp="2026-01-01T00:00:00Z",
            vulnerabilities=[
                Vulnerability(cve_id="CVE-1", severity=Severity.HIGH, package_name="bash"),
                Vulnerability(cve_id="CVE-2", severity=Severity.LOW, package_name="openssl"),
            ],
        )
        analyzer = HardeningAnalyzer(inspector=_StubInspector(HardeningFacts()))
        _, facts = await analyzer.analyze(DockerImage(name="node", tag="22"), scan)

        assert facts.has_shell is Tristate.TRUE
        assert facts.source_of("has_shell") is EvidenceSource.SCANNER
        # Nothing named a package manager, which proves nothing either way.
        assert facts.has_package_manager is Tristate.UNKNOWN

    async def test_the_package_count_is_never_derived_from_vulnerable_packages(self):
        scan = ScanResult(
            image_reference="node:22",
            status=ScanStatus.OK,
            scan_timestamp="2026-01-01T00:00:00Z",
            vulnerabilities=[
                Vulnerability(cve_id=f"CVE-{i}", severity=Severity.LOW, package_name=f"p{i}")
                for i in range(9)
            ],
        )
        analyzer = HardeningAnalyzer(inspector=_StubInspector(HardeningFacts()))
        _, facts = await analyzer.analyze(DockerImage(name="node", tag="22"), scan)
        assert facts.package_count is None

    async def test_an_inspector_that_raises_costs_facts_not_the_analysis(self):
        analyzer = HardeningAnalyzer(inspector=_ExplodingInspector())
        digest, facts = await analyzer.analyze(DockerImage(name="node", tag="22"), None)
        assert digest == ""
        assert facts.determined_count == 0

    async def test_no_inspector_means_everything_is_unknown(self):
        analyzer = HardeningAnalyzer(inspector=None)
        digest, facts = await analyzer.analyze(DockerImage(name="node", tag="22"), None)
        assert digest == ""
        assert facts.runs_as_non_root is Tristate.UNKNOWN
        assert await analyzer.resolve_digest(DockerImage(name="node", tag="22")) == ""


class TestMigrationPlanning:
    def test_a_libc_change_is_always_raised(self):
        plan = plan_migration(
            _analysis("node", "22-alpine", os_family="alpine"),
            _analysis("node", "22-bookworm-slim", os_family="debian"),
        )
        joined = " | ".join(plan.trade_offs)
        assert "musl -> glibc" in joined
        assert any("rebuild every native dependency for glibc" in s for s in plan.checklist)

    def test_an_unidentified_base_is_flagged_rather_than_assumed_compatible(self):
        plan = plan_migration(
            _analysis("node", "22", os_family=""),
            _analysis("cgr.dev/chainguard/node", "latest", os_family=""),
        )
        assert any("could not be identified" in cost for cost in plan.trade_offs)

    def test_the_same_libc_raises_no_libc_trade_off(self):
        plan = plan_migration(
            _analysis("node", "22-bookworm", os_family="debian"),
            _analysis("node", "22-noble", os_family="ubuntu"),
        )
        assert not any("C library changes" in cost for cost in plan.trade_offs)

    def test_a_package_manager_change_is_raised(self):
        plan = plan_migration(
            _analysis("node", "22-alpine", os_family="alpine"),
            _analysis("node", "22-bookworm", os_family="debian"),
        )
        assert any("package manager changes (apk -> apt)" in c for c in plan.trade_offs)

    def test_a_regression_is_reported_rather_than_hidden(self):
        plan = plan_migration(
            _analysis("node", "22", critical=0, score=90.0),
            _analysis("node", "20", critical=3, score=40.0),
        )
        assert plan.score_delta == -50.0
        assert plan.critical_delta == 3
        assert any("CRITICAL findings increase: 0 -> 3" in c for c in plan.trade_offs)

    def test_improvements_are_differences_between_measurements(self):
        plan = plan_migration(
            _analysis("node", "22", critical=2, high=4, score=45.0),
            _analysis("node", "22-slim", critical=0, high=1, score=88.0),
        )
        assert plan.score_delta == 43.0
        assert "CRITICAL: 2 -> 0" in plan.improvements
        assert "HIGH: 4 -> 1" in plan.improvements

    def test_a_missing_shell_is_both_a_gain_and_a_stated_cost(self):
        target = _analysis("cgr.dev/chainguard/node", "latest", os_family="wolfi")
        target.facts = HardeningFacts(has_shell=Tristate.FALSE, config_verified=True)
        plan = plan_migration(_analysis("node", "22-bookworm", os_family="debian"), target)
        assert any("no shell" in cost for cost in plan.trade_offs)
        assert any("exec form" in step for step in plan.checklist)

    def test_lost_architectures_are_named(self):
        current = _analysis("node", "22", os_family="debian")
        current.image.available_architectures = ["amd64", "arm64", "s390x"]
        target = _analysis("node", "22-slim", os_family="debian")
        target.image.available_architectures = ["amd64"]
        plan = plan_migration(current, target)
        assert any("arm64, s390x" in cost for cost in plan.trade_offs)

    def test_a_non_root_target_adds_an_ownership_step(self):
        current = _analysis("node", "22", os_family="debian")
        current.facts = HardeningFacts(runs_as_non_root=Tristate.FALSE, config_verified=True)
        target = _analysis("node", "22-slim", os_family="debian")
        target.facts = HardeningFacts(
            runs_as_non_root=Tristate.TRUE, user="node", config_verified=True
        )
        plan = plan_migration(current, target)
        assert "target runs as a non-root account by default" in plan.improvements
        assert any("filesystem ownership" in step for step in plan.checklist)

    def test_the_checklist_always_ends_in_verification(self):
        plan = plan_migration(_analysis("node", "22"), _analysis("node", "22-slim"))
        assert any("re-scan" in step for step in plan.checklist)
        assert "deploy to a canary before rolling out" in plan.checklist

    def test_a_pinned_target_is_carried_into_the_plan(self):
        target = _analysis("node", "22-slim")
        target.image.digest = "sha256:" + "d" * 64
        plan = plan_migration(_analysis("node", "22"), target)
        assert plan.to_pinned_reference == f"node@sha256:{'d' * 64}"
        assert "target can be pinned to an immutable digest" in plan.improvements


# --------------------------------------------------------------------------
# Doubles and builders
# --------------------------------------------------------------------------


class _StubInspector:
    def __init__(self, facts: HardeningFacts, digest: str = ""):
        self._facts = facts
        self._digest = digest

    async def inspect(self, image):
        return self._digest, self._facts

    async def resolve_digest(self, image):
        return self._digest

    async def close(self):
        return None


class _ExplodingInspector:
    async def inspect(self, image):
        raise RuntimeError("registry on fire")

    async def resolve_digest(self, image):
        raise RuntimeError("registry on fire")

    async def close(self):
        return None


def _analysis(
    name: str,
    tag: str,
    *,
    critical: int = 0,
    high: int = 0,
    score: float = 80.0,
    os_family: str = "",
) -> ImageAnalysis:
    vulns = [
        Vulnerability(cve_id=f"CVE-C{i}", severity=Severity.CRITICAL, package_name="openssl")
        for i in range(critical)
    ] + [
        Vulnerability(cve_id=f"CVE-H{i}", severity=Severity.HIGH, package_name="zlib")
        for i in range(high)
    ]
    return ImageAnalysis(
        image=DockerImage(name=name, tag=tag),
        scan=ScanResult(
            image_reference=f"{name}:{tag}",
            vulnerabilities=vulns,
            status=ScanStatus.OK,
            scan_timestamp="2026-01-01T00:00:00Z",
            os_family=os_family,
        ),
        security_score=score,
        tier="A",
        remediation_score=60,
        confidence=Confidence.HIGH,
        hardening=DimensionReport(),
        attack_surface=DimensionReport(),
    )
