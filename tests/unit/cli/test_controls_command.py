"""Testes para `dockerls controls`.

O comando existe para que alguém possa ler o regulamento inteiro antes de
produzir um Dockerfile que falhe. Os testes fixam três coisas: o catálogo
completo aparece, uma regra desconhecida falha em vez de responder vazio, e
`--format json` continua sendo JSON puro (nenhuma frase humana no stdout).
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from dockerls.cli.app import app
from dockerls.domain.security_controls import RULE_MAPPINGS
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK

runner = CliRunner()


def test_lists_every_catalogued_rule():
    result = runner.invoke(app, ["controls", "--no-color"])
    assert result.exit_code == EXIT_OK
    for mapping in RULE_MAPPINGS:
        assert mapping.rule_id in result.output


def test_single_rule_shows_its_rationale():
    result = runner.invoke(app, ["controls", "DF002", "--no-color"])
    assert result.exit_code == EXIT_OK
    assert "DF002" in result.output
    # A justificativa só aparece na visão detalhada; a listagem ficaria
    # ilegível com doze parágrafos.
    assert "uid 0" in result.output
    assert "DF001" not in result.output


def test_unknown_rule_fails_instead_of_answering_nothing():
    result = runner.invoke(app, ["controls", "DF999", "--no-color"])
    assert result.exit_code == EXIT_ERROR
    assert "DF999" in result.output


def test_json_output_is_parseable():
    result = runner.invoke(app, ["controls", "--format", "json"])
    assert result.exit_code == EXIT_OK
    payload = json.loads(result.output)
    assert len(payload) == len(RULE_MAPPINGS)
    entry = next(item for item in payload if item["rule_id"] == "DF002")
    assert entry["documented"] is True
    assert entry["rationale"]
    assert any("CIS Docker Benchmark 4.1" in c["reference"] for c in entry["controls"])


def test_json_output_of_unknown_rule_is_still_json():
    result = runner.invoke(app, ["controls", "DF999", "--format", "json"])
    assert result.exit_code == EXIT_ERROR
    payload = json.loads(result.output)
    assert "DF999" in payload["error"]
    assert "DF002" in payload["known_rules"]
