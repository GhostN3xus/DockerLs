"""Adversarial coverage for the two exploitable defects the audit found.

Both were reproducible against the installed package before the fix: an
image reference reaching the cloud metadata endpoint, and scanner-supplied
text being interpreted as terminal formatting. Both are pinned here so they
cannot come back quietly.
"""

from __future__ import annotations

import io
import ipaddress
import sys

import pytest
from rich.console import Console
from rich.table import Table

from dockerls.cli.text import safe
from dockerls.domain.value_objects.network_policy import (
    NetworkDecision,
    NetworkPolicy,
    hostname_of,
)
from dockerls.infrastructure.network.host_guard import HostGuard
from dockerls.infrastructure.redaction import MASK, redact
from dockerls.utils.subprocess_runner import OutputTooLargeError, run_capture


def _addresses(*values: str) -> list:
    return [ipaddress.ip_address(v) for v in values]


class TestSSRF:
    """An image reference is user input carrying a hostname."""

    @pytest.mark.parametrize(
        ("address", "expected"),
        [
            # The actual attack: cloud instance credentials.
            ("169.254.169.254", NetworkDecision.BLOCKED_LINK_LOCAL),
            ("fe80::1", NetworkDecision.BLOCKED_LINK_LOCAL),
            ("127.0.0.1", NetworkDecision.BLOCKED_LOOPBACK),
            ("127.1.2.3", NetworkDecision.BLOCKED_LOOPBACK),
            ("::1", NetworkDecision.BLOCKED_LOOPBACK),
            ("0.0.0.0", NetworkDecision.BLOCKED_UNSPECIFIED),  # noqa: S104 - test input
        ],
    )
    def test_dangerous_targets_are_refused_by_default(self, address, expected):
        assert NetworkPolicy().decide_addresses(_addresses(address)) is expected

    @pytest.mark.parametrize("address", ["10.0.0.5", "172.16.4.4", "192.168.1.10"])
    def test_private_registries_still_work(self, address):
        """The brief is explicit: internal registries are legitimate and must
        not be broken by an SSRF fix."""
        assert NetworkPolicy().decide_addresses(_addresses(address)) is NetworkDecision.ALLOWED

    def test_private_ranges_can_be_tightened(self):
        policy = NetworkPolicy(allow_private_networks=False)
        assert policy.decide_addresses(_addresses("10.0.0.5")) is NetworkDecision.BLOCKED_PRIVATE

    def test_a_mixed_answer_is_refused(self):
        """DNS rebinding: one public answer and one loopback answer. The
        connection would be free to use either, so the pair is refused."""
        decision = NetworkPolicy().decide_addresses(_addresses("93.184.216.34", "127.0.0.1"))
        assert decision is NetworkDecision.BLOCKED_LOOPBACK

    def test_an_allowlist_entry_wins(self):
        guard = HostGuard(NetworkPolicy(allowed_hosts=frozenset({"registry.internal:5000"})))
        assert guard.allows("registry.internal:5000") is True
        assert guard.decide("registry.internal:5000") is NetworkDecision.ALLOWED_BY_ALLOWLIST

    def test_localhost_is_judged_by_where_it_resolves_not_how_it_is_spelled(self):
        assert HostGuard().allows("localhost:5000") is False

    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            ("registry.example:5000", "registry.example"),
            ("registry.example", "registry.example"),
            ("[::1]:5000", "::1"),
            ("[fe80::1]", "fe80::1"),
            ("", ""),
        ],
    )
    def test_host_and_port_are_split_without_mangling_ipv6(self, host, expected):
        assert hostname_of(host) == expected

    def test_a_refusal_explains_itself_and_names_the_setting(self):
        guard = HostGuard()
        message = guard.explain("169.254.169.254")
        assert "169.254" in message
        assert "network_allow_link_local" in message


class TestTerminalInjection:
    """Scanner and catalogue text must render as text."""

    @pytest.mark.parametrize(
        "hostile",
        [
            "[red]FIXED - no action needed[/red]",
            "[blink]urgent[/blink]",
            "[on red]",
            "package[/]name",
        ],
    )
    def test_markup_in_third_party_text_is_not_interpreted(self, hostile):
        console = Console(file=io.StringIO(), width=120, no_color=True)
        table = Table()
        table.add_column("Package")
        table.add_row(safe(hostile))
        console.print(table)
        rendered = console.file.getvalue()
        # The brackets survive: the value was shown, not obeyed.
        assert hostile.split("]")[0] + "]" in rendered

    def test_ordinary_text_is_unchanged(self):
        assert safe("openssl 1.1.1") == "openssl 1.1.1"

    def test_none_and_non_strings_are_accepted(self):
        assert safe(None) == ""
        assert safe(42) == "42"


class TestScannerOutputIsBounded:
    async def test_a_scanner_that_never_stops_writing_is_cut_off(self):
        with pytest.raises(OutputTooLargeError):
            await run_capture(
                [sys.executable, "-c", "import sys\nwhile True: sys.stdout.write('x' * 65536)"],
                timeout=30,
                max_output_bytes=512 * 1024,
            )

    async def test_ordinary_output_is_returned_intact(self):
        code, stdout, _ = await run_capture(
            [sys.executable, "-c", "print('{\"ok\": true}')"], timeout=30
        )
        assert code == 0
        assert b'"ok"' in stdout


class TestEvidenceRedaction:
    @pytest.mark.parametrize(
        "leak",
        [
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
            '{"token": "dckr_pat_AbCdEf123456789xyz"}',
            "https://user:hunter2@registry.internal/v2/",
            "registry_password=s3cr3t",
        ],
    )
    def test_credentials_do_not_survive_redaction(self, leak):
        redacted = redact(leak)
        assert MASK in redacted
        for secret in ("eyJhbGciOiJIUzI1NiJ9", "dckr_pat_AbCdEf123456789xyz", "hunter2", "s3cr3t"):
            assert secret not in redacted

    def test_diagnostic_content_survives(self):
        """Redaction must not destroy the evidence it is protecting."""
        finding = (
            '{"VulnerabilityID": "CVE-2024-1234", "PkgName": "openssl", '
            '"InstalledVersion": "1.1.1", "FixedVersion": "1.1.1w", "Severity": "CRITICAL"}'
        )
        redacted = redact(finding)
        for kept in ("CVE-2024-1234", "openssl", "1.1.1w", "CRITICAL"):
            assert kept in redacted
