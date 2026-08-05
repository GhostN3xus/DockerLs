from dockerls.integrations.grype.scanner import GrypeScanner


class TestGrypeParser:
    def test_parse_results(self):
        scanner = GrypeScanner()
        data = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-1111",
                        "severity": "High",
                        "fix": {"versions": ["2.0.0"]},
                        "cvss": [{"metrics": {"baseScore": 8.1}}],
                    },
                    "artifact": {
                        "name": "libxml2",
                        "version": "1.9.0",
                    },
                },
                {
                    "vulnerability": {
                        "id": "CVE-2024-2222",
                        "severity": "Negligible",
                        "fix": {"versions": []},
                        "cvss": [],
                    },
                    "artifact": {"name": "zlib", "version": "1.2.11"},
                },
            ]
        }
        result = scanner._parse_results("python:3.12", data)
        assert result.high_count == 1
        assert result.low_count == 1
        assert result.fixable_count == 1
        assert result.vulnerabilities[0].cvss_score == 8.1

    def test_parse_empty(self):
        scanner = GrypeScanner()
        result = scanner._parse_results("nginx:latest", {"matches": []})
        assert result.total_count == 0
