"""Testes para o catálogo de controles publicados.

O valor deste catálogo está inteiramente na sua exatidão: uma citação errada
é pior do que nenhuma citação, porque um leitor que confere `CIS 4.1` e
encontra outro assunto passa a duvidar de todo o relatório. Estes testes
fixam as propriedades que uma citação errada quebraria -- cobertura de todas
as regras emitidas pelo validador, identificadores únicos, e a recusa em
inventar um controle para uma regra que não tem nenhum.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from dockerls.domain.security_controls import (
    RULE_MAPPINGS,
    Control,
    ControlSource,
    RuleMapping,
    controls_for,
    mapping_for,
    references_for,
)

_VALIDATOR = Path(__file__).resolve().parents[3] / "dockerls/infrastructure/dockerfile_validator.py"


def _rule_ids_emitted_by_the_validator() -> set[str]:
    source = _VALIDATOR.read_text(encoding="utf-8")
    return set(re.findall(r'rule_id="(DF\d+)"', source))


class TestCatalogueCoverage:
    def test_every_emitted_rule_is_catalogued(self):
        emitted = _rule_ids_emitted_by_the_validator()
        assert emitted, "o validador deveria emitir regras DFxxx"
        missing = sorted(rule for rule in emitted if mapping_for(rule) is None)
        assert missing == [], f"regras sem entrada no catálogo: {missing}"

    def test_catalogue_has_no_rule_the_validator_never_emits(self):
        emitted = _rule_ids_emitted_by_the_validator()
        orphans = sorted(m.rule_id for m in RULE_MAPPINGS if m.rule_id not in emitted)
        assert orphans == [], f"regras catalogadas que ninguém emite: {orphans}"

    def test_rule_ids_are_unique(self):
        ids = [mapping.rule_id for mapping in RULE_MAPPINGS]
        assert len(ids) == len(set(ids))


class TestCitationsAreUsable:
    @pytest.mark.parametrize("mapping", RULE_MAPPINGS, ids=lambda m: m.rule_id)
    def test_every_mapping_explains_itself(self, mapping: RuleMapping):
        assert mapping.summary.strip()
        # A justificativa é o que distingue uma regra de uma preferência.
        assert len(mapping.rationale.strip()) > 40

    @pytest.mark.parametrize("mapping", RULE_MAPPINGS, ids=lambda m: m.rule_id)
    def test_controls_quote_a_source_and_a_title(self, mapping: RuleMapping):
        for control in mapping.controls:
            assert isinstance(control.source, ControlSource)
            assert control.title.strip()
            # O identificador pode ser vazio (documentação citada por página),
            # mas a origem e o título nunca são.
            assert control.source.value in str(control)
            assert control.title in str(control)

    def test_numbered_controls_render_source_identifier_and_title(self):
        control = Control(ControlSource.CIS_DOCKER, "4.1", "Ensure that a user has been created")
        assert str(control) == ("CIS Docker Benchmark 4.1 -- Ensure that a user has been created")

    def test_unnumbered_controls_do_not_render_a_dangling_space(self):
        control = Control(ControlSource.DOCKER_DOCS, "", "Multi-stage builds")
        assert str(control) == "Docker documentation -- Multi-stage builds"


class TestLookupsRefuseToGuess:
    def test_unknown_rule_has_no_mapping(self):
        assert mapping_for("DF999") is None
        assert controls_for("DF999") == ()
        assert references_for("DF999") == []

    @pytest.mark.parametrize("value", ["", None, "   "])
    def test_absent_rule_id_is_not_an_error(self, value):
        assert mapping_for(value) is None
        assert references_for(value) == []

    def test_lookup_is_case_and_whitespace_insensitive(self):
        assert mapping_for(" df002 ") is mapping_for("DF002")

    def test_is_documented_distinguishes_our_opinion_from_a_published_control(self):
        undocumented = RuleMapping(rule_id="DFX", summary="s", rationale="r")
        assert undocumented.is_documented is False
        assert mapping_for("DF002") is not None
        assert mapping_for("DF002").is_documented is True

    def test_references_are_display_strings(self):
        references = references_for("DF002")
        assert references == [str(control) for control in controls_for("DF002")]
        assert all(isinstance(reference, str) for reference in references)
