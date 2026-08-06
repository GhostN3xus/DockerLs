from __future__ import annotations

from datetime import date, timedelta

from dockerls.utils.ignore_file import active_ignored_cve_ids, load_ignore_rules


class TestLoadIgnoreRules:
    def test_missing_file_returns_empty(self, tmp_path):
        rules = load_ignore_rules(tmp_path / "nope.yaml")
        assert rules == []

    def test_loads_valid_rules(self, tmp_path):
        f = tmp_path / ".dockerls-ignore.yaml"
        f.write_text(
            "ignores:\n"
            "  - cve: CVE-2024-0001\n"
            "    justification: not reachable\n"
        )
        rules = load_ignore_rules(f)
        assert len(rules) == 1
        assert rules[0].cve == "CVE-2024-0001"

    def test_expired_rule_is_dropped(self, tmp_path):
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        f = tmp_path / ".dockerls-ignore.yaml"
        f.write_text(
            "ignores:\n"
            f"  - cve: CVE-2024-0002\n"
            f"    justification: temp\n"
            f"    expires: {yesterday}\n"
        )
        rules = load_ignore_rules(f)
        assert rules == []

    def test_future_expiry_kept(self, tmp_path):
        tomorrow = (date.today() + timedelta(days=1)).isoformat()
        f = tmp_path / ".dockerls-ignore.yaml"
        f.write_text(
            "ignores:\n"
            f"  - cve: CVE-2024-0003\n"
            f"    expires: {tomorrow}\n"
        )
        rules = load_ignore_rules(f)
        assert len(rules) == 1

    def test_malformed_yaml_returns_empty(self, tmp_path):
        f = tmp_path / ".dockerls-ignore.yaml"
        f.write_text("ignores: [this is not: valid: yaml")
        assert load_ignore_rules(f) == []

    def test_active_ignored_cve_ids_normalizes_case(self, tmp_path):
        f = tmp_path / ".dockerls-ignore.yaml"
        f.write_text("ignores:\n  - cve: cve-2024-0004\n")
        rules = load_ignore_rules(f)
        assert active_ignored_cve_ids(rules) == {"CVE-2024-0004"}
