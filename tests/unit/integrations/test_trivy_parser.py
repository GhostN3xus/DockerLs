from dockerls.integrations.trivy.scanner import TrivyScanner


class TestTrivyParser:
    def test_parse_results(self):
        scanner = TrivyScanner()
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "Severity": "HIGH",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.1",
                            "FixedVersion": "3.0.2",
                            "Title": "Buffer overflow",
                            "CVSS": {"nvd": {"V3Score": 7.5}},
                        },
                        {
                            "VulnerabilityID": "CVE-2024-0002",
                            "Severity": "CRITICAL",
                            "PkgName": "curl",
                            "InstalledVersion": "7.88.0",
                            "FixedVersion": "",
                            "Title": "RCE in curl",
                        },
                    ]
                }
            ]
        }
        result = scanner._parse_results("node:22-alpine", data)
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.fixable_count == 1
        assert result.vulnerabilities[0].cvss_score == 7.5

    def test_parse_empty(self):
        scanner = TrivyScanner()
        result = scanner._parse_results("node:latest", {"Results": []})
        assert result.total_count == 0
