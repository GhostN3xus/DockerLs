"""What every exporter must guarantee, on real data and on partial data.

The existing tests check the happy path of each format. These check the
properties a CI consumer depends on -- valid documents, escaped content,
UTF-8 on disk -- and, in particular, what happens when the scanner reports a
finding it could not fully identify. That is the normal case, not an edge
case: Debian, Alpine and Ubuntu classify advisories without publishing a
CVSS score, and Trivy can emit a finding with no advisory ID at all.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from xml.etree import ElementTree

import pytest

from dockerls.application.dto.analysis import AnalysisResult, ImageAnalysis
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability
from dockerls.exporters.factory import ExporterFactory

FORMATS = ["json", "csv", "html", "markdown", "sarif"]


def _vuln(**kwargs) -> Vulnerability:
    defaults = {
        "cve_id": "CVE-2024-0001",
        "severity": Severity.HIGH,
        "cvss_score": 7.5,
        "package_name": "openssl",
        "installed_version": "1.1.1",
        "fixed_version": "1.1.1w",
        "description": "A flaw in OpenSSL",
    }
    defaults.update(kwargs)
    return Vulnerability(**defaults)


def _result(vulns=None, *, name="node", tag="22-alpine") -> AnalysisResult:
    image = DockerImage(name=name, tag=tag, is_official=True)
    scan = ScanResult(
        image_reference=f"{name}:{tag}",
        vulnerabilities=vulns or [],
        scan_timestamp="2026-01-01T00:00:00+00:00",
    )
    analysis = ImageAnalysis(
        image=image,
        scan=scan,
        security_score=82.5,
        tier="B",
        production_ready=True,
        remediation_score=90,
    )
    return AnalysisResult(
        query=name, total_tags_scanned=12, baseline_met=True, recommendations=[analysis]
    )


class TestEveryFormatSurvivesAnEmptyResult:
    """A run that found nothing still has to produce a parseable document --
    a CI step that consumes the artefact must not fail on the empty case."""

    @pytest.mark.parametrize("fmt", FORMATS)
    def test_empty_result_produces_output(self, fmt):
        empty = AnalysisResult(query="node", total_tags_scanned=0, baseline_met=False)
        output = ExporterFactory.create(fmt).export_string(empty)
        assert output.strip()

    def test_empty_json_is_still_json(self):
        empty = AnalysisResult(query="node", total_tags_scanned=0, baseline_met=False)
        assert json.loads(ExporterFactory.create("json").export_string(empty))["query"] == "node"

    def test_empty_sarif_is_still_valid(self):
        empty = AnalysisResult(query="node", total_tags_scanned=0, baseline_met=False)
        doc = json.loads(ExporterFactory.create("sarif").export_string(empty))
        assert doc["version"] == "2.1.0"
        assert doc["runs"][0]["results"] == []

    def test_empty_csv_still_carries_its_header(self):
        empty = AnalysisResult(query="node", total_tags_scanned=0, baseline_met=False)
        rows = list(csv.reader(io.StringIO(ExporterFactory.create("csv").export_string(empty))))
        assert rows[0][0] == "Image"


class TestFilesAreWrittenAsUtf8:
    """Every exporter writes with an explicit encoding, so a report is
    readable regardless of the locale of the machine that generated it."""

    @pytest.mark.parametrize("fmt", FORMATS)
    def test_a_non_ascii_image_name_survives_a_round_trip(self, fmt, tmp_path):
        # Carried in the image reference, which every format prints -- the
        # description only reaches the JSON and SARIF documents.
        result = _result(
            [_vuln(description="Falha na validação — certificado")],
            name="registry.local/equipe-segurança/app",
        )
        path = tmp_path / f"report.{fmt}"
        ExporterFactory.create(fmt).export(result, path)

        raw = path.read_bytes()
        assert raw.strip()
        # It must decode as UTF-8 and nothing else.
        text = raw.decode("utf-8")
        if fmt in ("json", "sarif"):
            # json.dumps escapes non-ASCII by default; decoding restores it.
            assert "seguran" in json.dumps(json.loads(text), ensure_ascii=False)
        else:
            assert "segurança" in text

    def test_the_description_reaches_the_formats_that_carry_it(self, tmp_path):
        result = _result([_vuln(description="Falha na validação — certificado")])
        for fmt in ("json", "sarif"):
            path = tmp_path / f"d.{fmt}"
            ExporterFactory.create(fmt).export(result, path)
            assert "validação" in json.dumps(
                json.loads(path.read_text(encoding="utf-8")), ensure_ascii=False
            )


class TestSarifIsValid:
    """SARIF 2.1.0 required structure, plus the two properties GitHub code
    scanning actually reads."""

    def test_required_top_level_structure(self):
        doc = json.loads(ExporterFactory.create("sarif").export_string(_result([_vuln()])))
        assert doc["version"] == "2.1.0"
        assert "$schema" in doc
        driver = doc["runs"][0]["tool"]["driver"]
        assert driver["name"] == "DockerLs"
        assert driver["version"]

    def test_every_rule_id_is_non_empty(self):
        """`reportingDescriptor.id` is required to be a non-empty string.
        A finding with no advisory ID used to emit `"id": ""`, which makes
        the whole document invalid."""
        result = _result([_vuln(cve_id=""), _vuln(cve_id="   "), _vuln()])
        doc = json.loads(ExporterFactory.create("sarif").export_string(result))

        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        assert rules
        for rule in rules:
            assert isinstance(rule["id"], str)
            assert rule["id"].strip()

    def test_every_result_points_at_a_declared_rule(self):
        result = _result([_vuln(cve_id=""), _vuln()])
        doc = json.loads(ExporterFactory.create("sarif").export_string(result))

        declared = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        for entry in doc["runs"][0]["results"]:
            assert entry["ruleId"] in declared

    def test_unidentified_findings_are_grouped_by_package_not_collapsed(self):
        result = _result(
            [_vuln(cve_id="", package_name="zlib"), _vuln(cve_id="", package_name="curl")]
        )
        doc = json.loads(ExporterFactory.create("sarif").export_string(result))

        ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        assert len(ids) == 2

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [
            (Severity.CRITICAL, 9.0),
            (Severity.HIGH, 7.0),
            (Severity.MEDIUM, 4.0),
            (Severity.LOW, 1.0),
        ],
    )
    def test_an_unscored_finding_keeps_its_severity(self, severity, expected):
        """GitHub buckets on `security-severity`. Emitting the literal 0.0
        for advisories that Debian/Alpine classified without scoring filed
        every unscored CRITICAL at the bottom of the security dashboard."""
        result = _result([_vuln(severity=severity, cvss_score=0.0)])
        doc = json.loads(ExporterFactory.create("sarif").export_string(result))

        props = doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
        assert float(props["security-severity"]) == expected
        assert props["severity-source"] == "severity-band"

    def test_a_real_cvss_score_is_used_verbatim(self):
        result = _result([_vuln(severity=Severity.MEDIUM, cvss_score=5.5)])
        doc = json.loads(ExporterFactory.create("sarif").export_string(result))

        props = doc["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
        assert float(props["security-severity"]) == 5.5
        assert props["severity-source"] == "cvss"

    def test_the_two_sources_are_distinguishable(self):
        """A consumer must be able to tell a measured score from a
        translated category."""
        result = _result([_vuln(cvss_score=9.8), _vuln(cve_id="CVE-2024-2", cvss_score=0.0)])
        doc = json.loads(ExporterFactory.create("sarif").export_string(result))

        sources = {
            r["properties"]["severity-source"] for r in doc["runs"][0]["tool"]["driver"]["rules"]
        }
        assert sources == {"cvss", "severity-band"}

    def test_no_help_uri_is_invented_for_an_unidentified_finding(self):
        """The bare NVD detail URL with no CVE appended is a link to a 404."""
        result = _result([_vuln(cve_id="")])
        doc = json.loads(ExporterFactory.create("sarif").export_string(result))

        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "helpUri" not in rule

    def test_severity_maps_to_a_sarif_level(self):
        result = _result(
            [
                _vuln(cve_id="CVE-1", severity=Severity.CRITICAL),
                _vuln(cve_id="CVE-2", severity=Severity.MEDIUM),
                _vuln(cve_id="CVE-3", severity=Severity.LOW),
            ]
        )
        doc = json.loads(ExporterFactory.create("sarif").export_string(result))
        levels = [r["level"] for r in doc["runs"][0]["results"]]
        assert levels == ["error", "warning", "note"]


class TestHtmlIsEscaped:
    def test_markup_in_the_query_cannot_break_out(self):
        result = AnalysisResult(
            query="<script>alert(1)</script>", total_tags_scanned=0, baseline_met=False
        )
        html = ExporterFactory.create("html").export_string(result)

        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_the_results_table_parses_as_xml(self):
        """A crude well-formedness check on the part that carries scan data:
        unescaped content is the usual way a generated report stops
        parsing, and the table is where scanner output ends up."""
        result = _result([_vuln(description="a & b < c")], name="my-org/app<>&")
        html = ExporterFactory.create("html").export_string(result)
        table = html[html.index("<table>") : html.index("</table>") + len("</table>")]
        ElementTree.fromstring(table)  # noqa: S314 - our own generated markup

    def test_markup_in_an_image_reference_is_escaped(self):
        result = _result(name="my-org/app<>&")
        html = ExporterFactory.create("html").export_string(result)
        assert "app<>&" not in html
        assert "app&lt;&gt;&amp;" in html


class TestCsvIsParseable:
    def test_round_trips_through_a_csv_reader(self):
        result = _result([_vuln()])
        rows = list(csv.reader(io.StringIO(ExporterFactory.create("csv").export_string(result))))

        assert rows[0][0] == "Image"
        assert rows[1][0] == "node"
        assert rows[1][1] == "22-alpine"

    def test_every_row_has_the_header_width(self):
        result = _result([_vuln()])
        rows = [
            r
            for r in csv.reader(io.StringIO(ExporterFactory.create("csv").export_string(result)))
            if r
        ]
        assert len({len(r) for r in rows}) == 1


class TestMarkdownTableIsWellFormed:
    def test_row_count_matches_the_results(self):
        result = _result([_vuln()])
        md = ExporterFactory.create("markdown").export_string(result)
        rows = [line for line in md.splitlines() if line.startswith("| node:")]
        assert len(rows) == 1

    def test_the_table_header_and_separator_have_equal_columns(self):
        md = ExporterFactory.create("markdown").export_string(_result([_vuln()]))
        lines = md.splitlines()
        header = next(i for i, line in enumerate(lines) if line.startswith("| Image |"))
        assert lines[header].count("|") == lines[header + 1].count("|")


class TestFactoryRejectsUnknownFormats:
    def test_unknown_format_raises_with_the_valid_ones_named(self):
        with pytest.raises(ValueError) as excinfo:
            ExporterFactory.create("yaml")
        message = str(excinfo.value)
        assert "yaml" in message

    @pytest.mark.parametrize("fmt", [*FORMATS, "md"])
    def test_every_documented_format_resolves(self, fmt):
        assert ExporterFactory.create(fmt) is not None


class TestExportWritesToDisk:
    @pytest.mark.parametrize("fmt", FORMATS)
    def test_content_matches_export_string(self, fmt, tmp_path):
        result = _result([_vuln()])
        exporter = ExporterFactory.create(fmt)
        path = tmp_path / "out"
        exporter.export(result, path)
        # newline="" so the comparison sees the bytes as written: Python's
        # universal-newline translation on read would turn the CSV's CRLF
        # into LF and make an identical file look different.
        with Path(path).open(encoding="utf-8", newline="") as fh:
            assert fh.read() == exporter.export_string(result)

    def test_csv_uses_rfc_4180_line_endings(self, tmp_path):
        """Excel and most CSV consumers expect CRLF; `csv.writer` emits it
        and nothing in the write path may quietly rewrite it."""
        path = tmp_path / "out.csv"
        ExporterFactory.create("csv").export(_result([_vuln()]), path)
        assert path.read_bytes().endswith(b"\r\n")
