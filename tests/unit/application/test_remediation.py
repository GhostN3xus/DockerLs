"""`--fix`: o patch de Dockerfile derivado dos achados.

A regra que governa este arquivo: **nenhuma ação pode ser inventada**. Cada
linha do patch tem de sair de um achado concreto, e o que não tem correção
publicada precisa aparecer como pendência, não sumir. Um gerador de
remediação que sugere o que não resolve é pior que nenhum -- ele transfere a
responsabilidade sem transferir a correção.
"""

from __future__ import annotations

import pytest

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.application.services.remediation import (
    build_remediation_plan,
    render_dockerfile_patch,
)
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Severity, Vulnerability

NPM_TARGET = "/usr/local/lib/node_modules/npm/node_modules/package-lock.json"
ALPINE_TARGET = "node:22-alpine (alpine 3.21.0)"
DEBIAN_TARGET = "node:22-bookworm-slim (debian 12.8)"


def _v(cve, *, package="pkg", fixed="1.1", package_type="", target=""):
    return Vulnerability(
        cve_id=cve,
        severity=Severity.HIGH,
        package_name=package,
        installed_version="1.0",
        fixed_version=fixed,
        package_type=package_type,
        target=target,
    )


def _analysis(vulns, name="node", tag="22-alpine"):
    return ImageAnalysis(
        image=DockerImage(name=name, tag=tag),
        scan=ScanResult(
            image_reference=f"{name}:{tag}",
            vulnerabilities=vulns,
            scan_timestamp="2026-01-01T00:00:00+00:00",
        ),
        security_score=36.0,
        tier="E",
        remediation_score=80,
    )


class TestBundledNpm:
    """O caso que motivou o item: as 16 vulnerabilidades de `node:22-alpine`
    estão no npm embutido, e remover o npm zera todas."""

    def _plan(self):
        return build_remediation_plan(
            _analysis(
                [_v(f"CVE-{i}", package_type="lang-pkgs", target=NPM_TARGET) for i in range(3)]
            )
        )

    def test_both_real_options_are_offered(self):
        titles = [a.title for a in self._plan().actions]

        assert "Update the bundled npm CLI" in titles
        assert "Remove the bundled npm CLI" in titles

    def test_each_option_claims_every_npm_finding(self):
        for action in self._plan().actions:
            assert action.fixes == 3

    def test_they_are_marked_as_mutually_exclusive(self):
        actions = self._plan().actions
        assert all(a.alternative_to for a in actions[:2])

    def test_only_one_is_left_uncommented_in_the_patch(self):
        patch = render_dockerfile_patch(self._plan())

        assert "\nRUN npm install -g npm@latest" in patch
        assert "\n# RUN rm -rf /usr/local/lib/node_modules/npm" in patch
        assert "pick one, not both" in patch

    def test_the_patch_says_apk_will_not_help(self):
        assert "apk/apt upgrade does not touch them" in render_dockerfile_patch(self._plan())


class TestOsPackages:
    @pytest.mark.parametrize(
        ("target", "expected"),
        [
            (ALPINE_TARGET, "apk upgrade --no-cache"),
            (DEBIAN_TARGET, "apt-get update && apt-get upgrade -y"),
            ("img (redhat 9)", "dnf upgrade -y"),
            ("img (suse 15)", "zypper update -y"),
        ],
    )
    def test_the_command_matches_the_reported_distro(self, target, expected):
        plan = build_remediation_plan(
            _analysis([_v("CVE-1", package_type="os-pkgs", target=target)])
        )

        assert any(expected in a.dockerfile for a in plan.actions)

    def test_an_unrecognised_distro_produces_no_guessed_command(self):
        """Melhor não emitir camada nenhuma que emitir a errada."""
        plan = build_remediation_plan(
            _analysis([_v("CVE-1", package_type="os-pkgs", target="img (plan9 4)")])
        )

        assert plan.actions == []
        assert plan.unresolved == ("CVE-1",)

    def test_unfixable_os_findings_do_not_produce_an_upgrade_layer(self):
        plan = build_remediation_plan(
            _analysis([_v("CVE-1", fixed="", package_type="os-pkgs", target=ALPINE_TARGET)])
        )

        assert plan.actions == []
        assert plan.unresolved == ("CVE-1",)


class TestLanguagePackages:
    def test_pip_findings_are_pinned_to_the_fixed_version(self):
        plan = build_remediation_plan(
            _analysis(
                [
                    _v(
                        "CVE-1",
                        package="requests",
                        fixed="2.32.4",
                        package_type="lang-pkgs",
                        target="/usr/lib/python3.12/site-packages",
                    )
                ],
                name="python",
                tag="3.12-slim",
            )
        )

        assert "pip install --no-cache-dir --upgrade requests==2.32.4" in plan.actions[0].dockerfile

    def test_a_pin_is_preferred_over_a_blind_upgrade(self):
        """O scanner já entregou a versão-alvo; 'atualize tudo e torça' é
        pior informação que a que já temos."""
        plan = build_remediation_plan(
            _analysis(
                [
                    _v(
                        "CVE-1",
                        package="lodash",
                        fixed="4.17.21",
                        package_type="lang-pkgs",
                        target="/app/node_modules/.package-lock.json",
                    )
                ]
            )
        )

        assert "lodash@4.17.21" in plan.actions[0].dockerfile

    def test_bundled_npm_is_not_duplicated_as_a_generic_upgrade(self):
        plan = build_remediation_plan(
            _analysis([_v("CVE-1", package="tar", package_type="lang-pkgs", target=NPM_TARGET)])
        )

        generic = [a for a in plan.actions if a.title == "Upgrade npm packages"]
        assert generic == []


class TestWhatItRefusesToClaim:
    def test_unfixable_findings_are_listed_not_hidden(self):
        vulns = [
            _v("CVE-FIX", package_type="os-pkgs", target=ALPINE_TARGET),
            _v("CVE-NOFIX", fixed="", package_type="os-pkgs", target=ALPINE_TARGET),
        ]
        patch = render_dockerfile_patch(build_remediation_plan(_analysis(vulns)))

        assert "CVE-NOFIX" in patch
        assert "no published fix" in patch

    def test_resolved_count_never_includes_the_unfixable(self):
        vulns = [
            _v("CVE-FIX", package_type="os-pkgs", target=ALPINE_TARGET),
            _v("CVE-NOFIX", fixed="", package_type="os-pkgs", target=ALPINE_TARGET),
        ]
        plan = build_remediation_plan(_analysis(vulns))

        assert plan.resolved_count == 1
        assert plan.unresolved == ("CVE-NOFIX",)

    def test_a_clean_image_gets_an_honest_empty_patch(self):
        patch = render_dockerfile_patch(build_remediation_plan(_analysis([])))

        assert "Nothing to remediate" in patch
        assert "FROM node:22-alpine" in patch
        # Nenhuma *diretiva* RUN -- a palavra ainda aparece na prosa do
        # cabeçalho, que é o que a asserção anterior confundia.
        directives = [
            ln.strip() for ln in patch.splitlines() if ln.strip() and not ln.strip().startswith("#")
        ]
        assert directives == ["FROM node:22-alpine"]

    def test_switching_base_is_suggested_only_when_something_remains(self):
        clean = build_remediation_plan(
            _analysis(
                [_v("CVE-1", package_type="os-pkgs", target=DEBIAN_TARGET)], tag="22-bookworm"
            )
        )
        assert clean.base_suggestion == ""

        leftover = build_remediation_plan(
            _analysis(
                [_v("CVE-1", fixed="", package_type="os-pkgs", target=DEBIAN_TARGET)],
                tag="22-bookworm",
            )
        )
        assert "minimal base" in leftover.base_suggestion

    def test_an_alpine_image_is_not_told_to_switch_to_alpine(self):
        plan = build_remediation_plan(
            _analysis([_v("CVE-1", fixed="", package_type="os-pkgs", target=ALPINE_TARGET)])
        )

        assert plan.base_suggestion == ""


class TestThePatchIsAValidDockerfile:
    def test_it_starts_from_the_analysed_image(self):
        patch = render_dockerfile_patch(
            build_remediation_plan(
                _analysis([_v("CVE-1", package_type="os-pkgs", target=ALPINE_TARGET)])
            )
        )

        from_lines = [ln for ln in patch.splitlines() if ln.startswith("FROM ")]
        assert from_lines == ["FROM node:22-alpine"]

    def test_every_non_comment_line_is_a_directive(self):
        patch = render_dockerfile_patch(
            build_remediation_plan(
                _analysis(
                    [
                        _v("CVE-1", package_type="os-pkgs", target=ALPINE_TARGET),
                        _v("CVE-2", package_type="lang-pkgs", target=NPM_TARGET),
                    ]
                )
            )
        )

        for line in patch.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            assert stripped.split()[0] in ("FROM", "RUN"), f"unexpected directive: {line}"

    def test_it_says_what_it_is_and_is_not(self):
        """Esta ferramenta nunca viu o Dockerfile de quem a executa; o
        cabeçalho não pode sugerir o contrário."""
        patch = render_dockerfile_patch(
            build_remediation_plan(
                _analysis([_v("CVE-1", package_type="os-pkgs", target=ALPINE_TARGET)])
            )
        )

        assert "not your Dockerfile" in patch
        assert "patch to apply" in patch
