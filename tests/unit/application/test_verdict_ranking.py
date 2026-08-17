"""The composition rules: what may outrank what, and what may never mask what.

The load-bearing test in this file is
`test_perfect_hardening_never_outranks_fewer_criticals`. If it ever fails,
the tool has started trading vulnerabilities for configuration -- which is
the failure mode the whole hardening dimension was designed to avoid.
"""

from __future__ import annotations

from dockerls.application.dto.analysis import DimensionReport, ImageAnalysis
from dockerls.application.services.verdict import (
    apply_facts,
    cross_validation_agreed,
    finalize_verdict,
    rank,
    ranking_key,
)
from dockerls.domain.entities.declared_metadata import DeclaredImageMetadata
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.image_facts import EvidenceSource, HardeningFacts
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.value_objects.confidence import Confidence
from dockerls.domain.value_objects.tristate import Tristate


def _scan(critical: int = 0, high: int = 0, *, verified: bool = True, **kwargs) -> ScanResult:
    vulns = [
        Vulnerability(cve_id=f"CVE-2024-{i}", severity=Severity.CRITICAL, package_name="openssl")
        for i in range(critical)
    ] + [
        Vulnerability(cve_id=f"CVE-2024-9{i}", severity=Severity.HIGH, package_name="zlib")
        for i in range(high)
    ]
    return ScanResult(
        image_reference="node:22",
        vulnerabilities=vulns,
        status=ScanStatus.OK if verified else ScanStatus.ERROR,
        scan_timestamp="2026-01-01T00:00:00Z" if verified else "",
        **kwargs,
    )


def _analysis(
    name: str = "node",
    tag: str = "22",
    score: float = 80.0,
    critical: int = 0,
    high: int = 0,
    **kwargs,
) -> ImageAnalysis:
    return ImageAnalysis(
        image=DockerImage(name=name, tag=tag, **kwargs.pop("image_kwargs", {})),
        scan=_scan(critical, high),
        security_score=score,
        tier="A",
        remediation_score=50,
        **kwargs,
    )


class TestRankingPolicy:
    def test_perfect_hardening_never_outranks_fewer_criticals(self):
        """The rule the prompt calls out explicitly, pinned as a test.

        A flawlessly configured image with a CRITICAL must lose to an
        unremarkable image without one, at every hardening value.
        """
        hardened = _analysis("hardened", score=60.0, critical=2)
        hardened.hardening = DimensionReport(score=100.0, coverage=1.0, reportable=True)
        hardened.attack_surface = DimensionReport(score=0.0, coverage=1.0, reportable=True)
        hardened.confidence = Confidence.HIGH

        plain = _analysis("plain", score=88.0, critical=0)
        plain.hardening = DimensionReport(score=10.0, coverage=1.0, reportable=True)
        plain.attack_surface = DimensionReport(score=90.0, coverage=1.0, reportable=True)
        plain.confidence = Confidence.HIGH

        assert rank([hardened, plain])[0] is plain

    def test_confidence_outranks_every_other_dimension(self):
        weak_evidence = _analysis("unpinned", score=99.0)
        weak_evidence.confidence = Confidence.LOW
        weak_evidence.hardening = DimensionReport(score=100.0, coverage=1.0, reportable=True)

        measured = _analysis("measured", score=70.0)
        measured.confidence = Confidence.HIGH

        assert rank([weak_evidence, measured])[0] is measured

    def test_hardening_breaks_ties_between_equal_security_scores(self):
        soft = _analysis("soft", score=80.0)
        soft.confidence = Confidence.HIGH
        soft.hardening = DimensionReport(score=20.0, coverage=1.0, reportable=True)

        hard = _analysis("hard", score=80.0)
        hard.confidence = Confidence.HIGH
        hard.hardening = DimensionReport(score=95.0, coverage=1.0, reportable=True)

        assert rank([soft, hard])[0] is hard

    def test_thin_coverage_hardening_does_not_win_a_tie(self):
        """A 100 computed from one fact must not beat a measured 85."""
        thin = _analysis("thin", score=80.0)
        thin.confidence = Confidence.HIGH
        thin.hardening = DimensionReport(score=100.0, coverage=0.1, reportable=False)

        measured = _analysis("measured", score=80.0)
        measured.confidence = Confidence.HIGH
        measured.hardening = DimensionReport(score=85.0, coverage=0.9, reportable=True)

        assert rank([thin, measured])[0] is measured

    def test_lower_attack_surface_wins_when_all_else_is_equal(self):
        wide = _analysis("wide", score=80.0)
        wide.confidence = Confidence.HIGH
        wide.attack_surface = DimensionReport(score=90.0, coverage=1.0, reportable=True)

        narrow = _analysis("narrow", score=80.0)
        narrow.confidence = Confidence.HIGH
        narrow.attack_surface = DimensionReport(score=5.0, coverage=1.0, reportable=True)

        assert rank([wide, narrow])[0] is narrow

    def test_ranking_key_is_a_total_order(self):
        analyses = [_analysis(f"i{i}", score=float(i)) for i in range(5)]
        keys = [ranking_key(a) for a in analyses]
        assert len(set(keys)) == len(keys)
        assert rank(analyses)[0].security_score == 4.0


class TestExplanation:
    def test_a_clean_pinned_image_explains_itself(self):
        analysis = _analysis(image_kwargs={"digest": "sha256:" + "a" * 64})
        analysis.hub_tag_verified = True
        apply_facts(
            analysis,
            HardeningFacts(
                runs_as_non_root=Tristate.TRUE,
                user="node",
                has_shell=Tristate.FALSE,
                has_package_manager=Tristate.FALSE,
                config_verified=True,
                evidence={"runs_as_non_root": EvidenceSource.REGISTRY},
            ),
        )
        finalize_verdict(analysis, cross_validated=False)

        assert "no CRITICAL vulnerabilities" in analysis.why
        assert any("non-root" in reason for reason in analysis.why)
        assert "pinned to a resolved manifest digest" in analysis.why
        assert "tag confirmed in its source registry" in analysis.why

    def test_reasons_are_never_duplicated(self):
        analysis = _analysis()
        apply_facts(
            analysis,
            HardeningFacts(
                runs_as_non_root=Tristate.TRUE,
                has_shell=Tristate.FALSE,
                has_package_manager=Tristate.FALSE,
                has_debug_tools=Tristate.FALSE,
                config_verified=True,
            ),
        )
        finalize_verdict(analysis, cross_validated=False)
        assert len(analysis.why) == len(set(analysis.why))
        assert len(analysis.trade_offs) == len(set(analysis.trade_offs))

    def test_trade_offs_state_the_costs(self):
        analysis = _analysis(critical=1, high=3)
        analysis.is_eol = True
        analysis.scan_divergence = "CRITICAL trivy=1 vs grype=4"
        apply_facts(analysis, HardeningFacts(runs_as_non_root=Tristate.FALSE, config_verified=True))
        finalize_verdict(analysis, cross_validated=True)

        joined = " | ".join(analysis.trade_offs)
        assert "CRITICAL" in joined
        assert "end-of-life" in joined
        assert "root" in joined
        assert "no manifest digest resolved" in joined

    def test_a_declared_conflict_appears_as_a_trade_off(self):
        analysis = _analysis()
        facts = HardeningFacts(conflicts=["the catalogue declares X, but the registry disagrees"])
        apply_facts(analysis, facts)
        finalize_verdict(analysis, cross_validated=False)
        assert "the catalogue declares X, but the registry disagrees" in analysis.trade_offs

    def test_dev_variants_are_called_out(self):
        analysis = ImageAnalysis(
            image=DockerImage(
                name="dhi.io/node",
                tag="22-dev",
                declared=DeclaredImageMetadata(variant="dev", catalog="Docker Hardened Images"),
            ),
            scan=_scan(),
            security_score=90.0,
            tier="A",
            remediation_score=100,
        )
        apply_facts(analysis, HardeningFacts())
        finalize_verdict(analysis, cross_validated=False)
        assert any("ships build tooling by design" in cost for cost in analysis.trade_offs)


class TestCrossValidationDetection:
    def test_one_scanner_is_not_agreement(self):
        analysis = _analysis()
        analysis.evidence_paths = {"trivy": "evidence/trivy.json"}
        assert cross_validation_agreed(analysis) is False

    def test_two_scanners_with_no_divergence_is_agreement(self):
        analysis = _analysis()
        analysis.evidence_paths = {"trivy": "evidence/trivy.json", "grype": "evidence/grype.json"}
        assert cross_validation_agreed(analysis) is True

    def test_two_scanners_that_diverge_is_not_agreement(self):
        analysis = _analysis()
        analysis.evidence_paths = {"trivy": "evidence/trivy.json", "grype": "evidence/grype.json"}
        analysis.scan_divergence = "CRITICAL trivy=0 vs grype=3"
        assert cross_validation_agreed(analysis) is False
