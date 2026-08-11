"""Contadores de um scan não podem vazar para o scan seguinte.

Este arquivo existe por causa de uma suspeita concreta: `node:22-alpine`
reportava `Fixable: 16` de 16, e `node:22-bookworm-slim` reportava `Fixable:
16` de 170 -- o mesmo 16, o que parecia acumulador compartilhado.

Não era. `fixable_count` é uma property calculada sobre a própria lista da
instância, e as duas imagens de fato compartilham as 16 vulnerabilidades do
npm embutido (o mesmo relatório dizia "Shared vulnerabilities: 16"). As
extras do Debian são, na maioria, sem correção disponível -- daí o 16 nos
dois casos. Como a hipótese de estado compartilhado é barata de descartar e
cara de descobrir tarde, ela fica travada aqui.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.domain.value_objects.remediation_score import RemediationScore


def _vuln(index: int, *, fixable: bool, severity: Severity = Severity.HIGH) -> Vulnerability:
    return Vulnerability(
        cve_id=f"CVE-2026-{index:05d}",
        severity=severity,
        fixed_version="1.1.0" if fixable else "",
    )


def _scan(reference: str, total: int, fixable: int) -> ScanResult:
    return ScanResult(
        image_reference=reference,
        scan_timestamp=datetime.now(tz=UTC).isoformat(),
        vulnerabilities=[_vuln(i, fixable=i < fixable) for i in range(total)],
    )


class TestCountersAreInstanceScoped:
    def test_two_scans_in_one_process_keep_separate_counts(self):
        """Reproduz a forma exata da saída suspeita: 16/16 e 16/170."""
        alpine = _scan("node:22-alpine", total=16, fixable=16)
        slim = _scan("node:22-bookworm-slim", total=170, fixable=16)

        assert (alpine.total_count, alpine.fixable_count) == (16, 16)
        assert (slim.total_count, slim.fixable_count) == (170, 16)

    def test_order_of_construction_does_not_matter(self):
        slim = _scan("slim", total=170, fixable=16)
        alpine = _scan("alpine", total=16, fixable=16)

        assert slim.fixable_count == 16
        assert alpine.fixable_count == 16

    def test_many_scans_in_sequence_never_accumulate(self):
        counts = [_scan(f"img:{n}", total=n, fixable=n).fixable_count for n in range(1, 25)]

        assert counts == list(range(1, 25))

    def test_severity_counters_are_independent_too(self):
        first = ScanResult(
            image_reference="a",
            vulnerabilities=[_vuln(i, fixable=True, severity=Severity.CRITICAL) for i in range(3)],
        )
        second = ScanResult(
            image_reference="b",
            vulnerabilities=[_vuln(i, fixable=True, severity=Severity.LOW) for i in range(7)],
        )

        assert (first.critical_count, first.low_count) == (3, 0)
        assert (second.critical_count, second.low_count) == (0, 7)


class TestRemediationScoreIsAnOrdinalBand:
    """Não é a porcentagem de vulnerabilidades corrigíveis.

    16 de 170 é 9,4% e vale 20 -- o que parece "errado por um fator de dois"
    até você saber que 20 é o degrau mais baixo de uma escala de cinco, e não
    um percentual. O defeito real estava no rótulo: o terminal imprimia `20%`.
    """

    @pytest.mark.parametrize(
        ("total", "fixable", "expected"),
        [
            (0, 0, 100),
            (16, 16, 100),
            (100, 100, 100),
            (100, 80, 80),
            (100, 75, 80),
            (100, 74, 60),
            (100, 50, 60),
            (100, 49, 40),
            (100, 25, 40),
            (100, 24, 20),
            (170, 16, 20),
            (100, 0, 20),
        ],
    )
    def test_band_boundaries(self, total, fixable, expected):
        assert RemediationScore(_scan("x", total, fixable)).value == expected

    def test_the_documented_example_holds(self):
        """Os dois casos exatos da saída que motivou o relato."""
        assert RemediationScore(_scan("node:22-alpine", 16, 16)).value == 100
        assert RemediationScore(_scan("node:22-bookworm-slim", 170, 16)).value == 20

    def test_the_docstring_documents_the_formula(self):
        """A fórmula precisa estar escrita onde quem lê o número a procura."""
        doc = RemediationScore.__doc__ or ""
        assert "fixable / total" in doc
        assert "porcentagem" in doc.lower()
