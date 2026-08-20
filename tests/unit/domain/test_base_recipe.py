"""Gerar uma imagem base a partir de escolhas, com as recusas certas.

Uma imagem base é o piso de tudo que vem depois: cada pacote marcado existe em
toda aplicação que a consome. As recusas aqui não são preciosismo -- são o que
impede que a conveniência de uma pessoa vire superfície de ataque de um time
inteiro.
"""

from __future__ import annotations

import pytest

from dockerls.domain.value_objects.base_recipe import (
    PACKAGE_CATALOG,
    REFUSED_PACKAGES,
    RUNTIME_BASES,
    BaseRecipe,
    OsFamily,
    Runtime,
    UnsupportedCombinationError,
    render,
)

_DIGEST = "sha256:" + "a" * 64


class TestRefusals:
    def test_distroless_refuses_packages_and_explains_why(self):
        recipe = BaseRecipe(family=OsFamily.DISTROLESS, runtime=Runtime.JAVA, packages=("curl",))
        with pytest.raises(UnsupportedCombinationError, match="gerenciador de pacotes"):
            recipe.validate()

    def test_distroless_without_packages_is_fine(self):
        render(BaseRecipe(family=OsFamily.DISTROLESS, runtime=Runtime.JAVA))

    @pytest.mark.parametrize("package", sorted(REFUSED_PACKAGES))
    def test_dangerous_packages_are_refused_with_a_reason(self, package):
        recipe = BaseRecipe(family=OsFamily.ALPINE, packages=(package,))
        with pytest.raises(UnsupportedCombinationError) as excinfo:
            recipe.validate()
        # A recusa carrega o motivo: quem procurou por ele merece a explicação.
        assert REFUSED_PACKAGES[package][:20] in str(excinfo.value)

    def test_sudo_is_not_even_in_the_catalog(self):
        assert "sudo" not in {choice.key for choice in PACKAGE_CATALOG}

    def test_an_unknown_package_is_refused(self):
        with pytest.raises(UnsupportedCombinationError, match="desconhecido"):
            BaseRecipe(family=OsFamily.ALPINE, packages=("inexistente",)).validate()

    def test_a_runtime_without_a_published_base_is_refused(self):
        with pytest.raises(UnsupportedCombinationError, match="não há imagem base"):
            BaseRecipe(family=OsFamily.UBUNTU, runtime=Runtime.GO).validate()


class TestRendering:
    def _render(self, **kwargs) -> str:
        return render(BaseRecipe(digest=_DIGEST, **kwargs))

    def test_the_base_is_pinned_by_digest(self):
        out = self._render(family=OsFamily.ALPINE, runtime=Runtime.JAVA)
        assert f"ARG BASE_DIGEST={_DIGEST}" in out
        assert "FROM eclipse-temurin:21-jre-alpine@${BASE_DIGEST}" in out

    def test_without_a_digest_the_file_says_so_out_loud(self):
        out = render(BaseRecipe(family=OsFamily.ALPINE))
        # Uma base móvel propaga a incerteza para todo projeto que consome.
        assert "ATENÇÃO" in out
        assert "não fixada por digest" in out

    def test_alpine_uses_apk_and_debian_uses_apt(self):
        alpine = self._render(family=OsFamily.ALPINE, packages=("curl",))
        debian = self._render(family=OsFamily.DEBIAN, packages=("curl",))
        assert "apk add --no-cache" in alpine
        assert "apt-get install" in debian

    def test_the_package_index_is_removed_in_the_same_layer(self):
        # Removê-lo numa camada seguinte deixaria os bytes na anterior.
        debian = self._render(family=OsFamily.DEBIAN, packages=("curl",))
        assert "rm -rf /var/lib/apt/lists/*" in debian
        assert debian.count("RUN apt-get update") == 1

    def test_the_system_is_upgraded_even_without_packages(self):
        out = self._render(family=OsFamily.ALPINE)
        assert "apk upgrade --no-cache" in out

    def test_a_builtin_user_is_reused_instead_of_duplicated(self):
        # A imagem oficial do Node já traz o usuário `node`; criar outro por
        # cima confundiria quem consome.
        out = self._render(family=OsFamily.ALPINE, runtime=Runtime.NODE)
        assert "USER node" in out
        assert "adduser" not in out

    def test_a_family_without_a_builtin_user_gets_one_with_a_high_uid(self):
        out = self._render(family=OsFamily.ALPINE, runtime=Runtime.JAVA)
        assert "adduser -u 10001" in out
        assert "USER appuser" in out

    def test_no_entrypoint_expose_or_healthcheck(self):
        # Uma imagem base não sabe em que porta a aplicação escuta.
        out = self._render(family=OsFamily.ALPINE, runtime=Runtime.JAVA)
        for directive in ("ENTRYPOINT", "EXPOSE", "HEALTHCHECK"):
            assert f"\n{directive}" not in out

    def test_the_required_security_labels_are_present(self):
        out = self._render(
            family=OsFamily.ALPINE, owner="Plataforma", source="https://git/r", title="base-java"
        )
        assert 'maintainer="Plataforma"' in out
        assert 'security.scanner="dockerls"' in out
        assert 'org.opencontainers.image.source="https://git/r"' in out

    def test_empty_labels_are_omitted_not_written_blank(self):
        out = self._render(family=OsFamily.ALPINE)
        assert 'maintainer=""' not in out
        assert 'org.opencontainers.image.source=""' not in out


class TestCatalogIntegrity:
    def test_every_published_combination_renders(self):
        for runtime, family in RUNTIME_BASES:
            render(BaseRecipe(family=family, runtime=runtime, digest=_DIGEST))

    def test_every_package_names_a_purpose_and_a_cost(self):
        for choice in PACKAGE_CATALOG:
            assert choice.purpose.strip()
            # O custo é dito na hora de marcar, não descoberto depois.
            assert len(choice.cost.strip()) > 15

    def test_alpine_only_packages_are_skipped_on_debian(self):
        libc_compat = next(c for c in PACKAGE_CATALOG if c.key == "libc6-compat")
        assert libc_compat.package_for(OsFamily.ALPINE) == "libc6-compat"
        assert libc_compat.package_for(OsFamily.DEBIAN) == ""
