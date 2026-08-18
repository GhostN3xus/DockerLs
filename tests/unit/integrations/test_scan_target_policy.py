"""O scanner puxa a imagem sozinho — e isso também passa pela política.

O guarda de SSRF protegia o inspector de registry, que é *uma* das portas.
`trivy image X` e `grype X` abrem o próprio socket: uma referência como
`169.254.169.254/latest:v1` mirava a conexão do scanner no endpoint de
metadados da nuvem enquanto a porta guardada continuava fechada. Estes testes
fixam que a recusa acontece antes do binário ser invocado e que ela produz um
ERRO — nunca uma lista de achados vazia, que seria indistinguível de uma
imagem limpa.
"""

from __future__ import annotations

import ipaddress
from unittest.mock import AsyncMock, patch

import pytest

from dockerls.domain.entities.scan_result import ScanErrorKind, ScanStatus
from dockerls.domain.value_objects.image_reference import registry_host_of
from dockerls.domain.value_objects.network_policy import NetworkPolicy
from dockerls.infrastructure.network.host_guard import HostGuard
from dockerls.integrations.grype.scanner import GrypeScanner
from dockerls.integrations.trivy.scanner import TrivyScanner


@pytest.fixture
def guard_resolving(monkeypatch):
    """Constrói um guarda com DNS falso, para testar a política sem rede.

    O patch sai junto com o teste: um `patcher.start()` sem `stop()` deixaria
    a resolução falsa valendo para a suíte inteira.
    """

    def build(mapping: dict[str, list[str]]) -> HostGuard:
        def fake_resolve(hostname: str):
            return [ipaddress.ip_address(a) for a in mapping.get(hostname, [])]

        monkeypatch.setattr("dockerls.infrastructure.network.host_guard._resolve", fake_resolve)
        return HostGuard(NetworkPolicy())

    return build


class TestRegistryHostExtraction:
    @pytest.mark.parametrize(
        ("reference", "expected"),
        [
            ("node:22", ""),
            ("library/node:22", ""),
            ("docker.io/library/node:22", ""),
            ("index.docker.io/library/node", ""),
            ("ghcr.io/org/app:1.0", "ghcr.io"),
            ("registry.internal:5000/team/app", "registry.internal:5000"),
            ("169.254.169.254/latest:v1", "169.254.169.254"),
            # O caso que um teste de "ponto ou dois-pontos" perde: sem esta
            # linha, `localhost/evil` é lido como o usuário "localhost" do
            # Docker Hub e o pull chega num serviço desta máquina.
            ("localhost/evil", "localhost"),
            ("localhost:5000/x", "localhost:5000"),
            ("", ""),
        ],
    )
    def test_host_is_extracted_by_dockers_own_rule(self, reference, expected):
        assert registry_host_of(reference) == expected

    def test_digest_suffix_is_not_mistaken_for_a_port(self):
        assert registry_host_of("node@sha256:" + "a" * 64) == ""


@pytest.mark.asyncio
class TestScannersHonourThePolicy:
    async def test_trivy_refuses_the_metadata_endpoint(self, guard_resolving):
        guard = guard_resolving({"169.254.169.254": ["169.254.169.254"]})
        scanner = TrivyScanner(guard=guard)
        with patch(
            "dockerls.integrations.trivy.scanner.run_capture", new=AsyncMock()
        ) as run_capture:
            result = await scanner.scan("169.254.169.254/latest:v1")
        # O binário nunca foi invocado: a recusa acontece antes do subprocesso.
        run_capture.assert_not_called()
        assert result.status == ScanStatus.ERROR
        assert result.error_kind == ScanErrorKind.BLOCKED_BY_POLICY
        assert "link-local" in result.error_message

    async def test_grype_refuses_loopback(self, guard_resolving):
        guard = guard_resolving({"localhost": ["127.0.0.1"]})
        scanner = GrypeScanner(guard=guard)
        with patch(
            "dockerls.integrations.grype.scanner.run_capture", new=AsyncMock()
        ) as run_capture:
            result = await scanner.scan("localhost:5000/app:1")
        run_capture.assert_not_called()
        assert result.error_kind == ScanErrorKind.BLOCKED_BY_POLICY

    async def test_a_refusal_is_never_an_empty_finding_list(self, guard_resolving):
        guard = guard_resolving({"169.254.169.254": ["169.254.169.254"]})
        result = await TrivyScanner(guard=guard).scan("169.254.169.254/x:1")
        # Zero vulnerabilidades com status ERROR é "não medido", e o resto do
        # pipeline já trata não-medido como não-verificado.
        assert result.status != ScanStatus.OK
        assert result.vulnerabilities == []
        assert result.error_message

    async def test_sbom_generation_refuses_the_same_targets(self, guard_resolving):
        guard = guard_resolving({"169.254.169.254": ["169.254.169.254"]})
        scanner = TrivyScanner(guard=guard)
        with patch(
            "dockerls.integrations.trivy.scanner.run_capture", new=AsyncMock()
        ) as run_capture:
            assert await scanner.generate_sbom("169.254.169.254/x:1") is None
        run_capture.assert_not_called()

    async def test_a_private_registry_is_still_scannable(self, guard_resolving):
        # O contrário do ataque: registries internos em RFC1918 são
        # infraestrutura legítima e continuam passando.
        guard = guard_resolving({"registry.internal": ["10.0.0.5"]})
        scanner = TrivyScanner(guard=guard)
        with patch(
            "dockerls.integrations.trivy.scanner.run_capture",
            new=AsyncMock(return_value=(0, b'{"Results": []}', b"")),
        ) as run_capture:
            result = await scanner.scan("registry.internal:5000/team/app:1")
        run_capture.assert_called_once()
        assert result.status == ScanStatus.OK

    async def test_docker_hub_is_never_judged(self, guard_resolving):
        guard = guard_resolving({})
        scanner = TrivyScanner(guard=guard)
        with patch(
            "dockerls.integrations.trivy.scanner.run_capture",
            new=AsyncMock(return_value=(0, b'{"Results": []}', b"")),
        ) as run_capture:
            result = await scanner.scan("node:22")
        run_capture.assert_called_once()
        assert result.status == ScanStatus.OK

    async def test_without_a_guard_nothing_changes(self, guard_resolving):
        # Compatibilidade: um scanner construído sem política roda como antes.
        scanner = TrivyScanner()
        with patch(
            "dockerls.integrations.trivy.scanner.run_capture",
            new=AsyncMock(return_value=(0, b'{"Results": []}', b"")),
        ) as run_capture:
            await scanner.scan("ghcr.io/org/app:1")
        run_capture.assert_called_once()


class TestBlockedByPolicyIsNotAScannerFault:
    def test_a_second_scanner_would_be_blocked_identically(self):
        # Fazer fallback para o outro scanner só gastaria o dobro do tempo
        # para pular do mesmo host recusado.
        assert ScanErrorKind.BLOCKED_BY_POLICY.is_scanner_fault is False
